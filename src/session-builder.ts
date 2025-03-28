import { PreKeyWhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts'
import * as base64 from 'base64-js'
import { arrayBufferToString, uint8ArrayToArrayBuffer } from './helpers'
import * as Internal from './internal'
import { SessionLock } from './session-lock'
import { SessionRecord } from './session-record'
import { BaseKeyType, ChainType, DeviceType, SessionType } from './session-types'
import { Direction, KeyPairType, LoggerType, SignalProtocolAddressType, StorageType } from './types'

export class SessionBuilder {
    remoteAddress: SignalProtocolAddressType
    storage: StorageType
    logger: LoggerType

    constructor(storage: StorageType, remoteAddress: SignalProtocolAddressType, logger: LoggerType) {
        this.remoteAddress = remoteAddress
        this.storage = storage
        this.logger = logger
    }

    processPreKeyJob = async (device: DeviceType): Promise<SessionType> => {
        const trusted = await this.storage.isTrustedIdentity(
            this.remoteAddress.toString(),
            device.identityKey,
            Direction.SENDING
        )

        if (!trusted) {
            this.logger.sendEvent(`1-1-create-sender-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'processPreKeyJob',
                error: `Identity key changed`,
            })
            throw new Error('Identity key changed')
        }

        // Verify the signature of the identity
        await Internal.crypto.Ed25519Verify(
            device.identityKey,
            device.signedPreKey.publicKey,
            device.signedPreKey.signature
        ) // This will throw if invalid

        const ephemeralKey = await Internal.crypto.createKeyPair()

        const deviceOneTimePreKey = device.preKey?.publicKey

        this.logger.sendEvent(`1-1-create-sender-session:address=${this.remoteAddress.toString()}`, {
            functionName: 'processPreKeyJob',
            info: `Start creating session as initiator with preKeyBundle: preKeyId= ${device.preKey?.keyId} and signedPreKeyId ${device.signedPreKey.keyId}`,
        })

        const session = await this.startSessionAsInitiator(
            ephemeralKey,
            device.identityKey,
            device.signedPreKey.publicKey,
            deviceOneTimePreKey,
            device.registrationId
        )

        session.pendingPreKey = {
            signedKeyId: device.signedPreKey.keyId,
            baseKey: ephemeralKey.pubKey,
        }

        if (device.preKey) {
            session.pendingPreKey.preKeyId = device.preKey.keyId
        }

        const address = this.remoteAddress.toString()
        const serialized = await this.storage.loadSession(address)
        let record: SessionRecord
        if (serialized !== undefined) {
            record = SessionRecord.deserialize(serialized)
        } else {
            record = new SessionRecord()
        }
        // close open sessions if any
        record.archiveCurrentState()
        // cleanup the expired sessions and chains and set the new session as the open session
        record.updateSessionState(session)
        await Promise.all([
            this.storage.storeSession(address, record.serialize()),
            this.storage.saveIdentity(this.remoteAddress.toString(), session.indexInfo.remoteIdentityKey),
        ])

        this.logger.sendEvent(`1-1-create-sender-session:address=${this.remoteAddress.toString()}`, {
            functionName: 'processPreKeyJob',
            info: `Successfully created and saved session for preKeyId ${device.preKey?.keyId} and signedPreKeyId ${device.signedPreKey.keyId}`,
        })

        return session
    }

    // Arguments map to the X3DH spec: https://signal.org/docs/specifications/x3dh/#keys
    // We are Alice the initiator.
    startSessionAsInitiator = async (
        EKa: KeyPairType<ArrayBuffer>,
        IKb: ArrayBuffer,
        SPKb: ArrayBuffer,
        OPKb: ArrayBuffer | undefined,
        registrationId?: number
    ): Promise<SessionType> => {
        const IKa = await this.storage.getIdentityKeyPair()

        if (!IKa) {
            this.logger.sendEvent(`1-1-create-sender-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'startSessionAsInitiator',
                error: `No identity key. Cannot initiate session.`,
            })
            throw new Error(`No identity key. Cannot initiate session.`)
        }

        let sharedSecret: Uint8Array
        if (OPKb === undefined) {
            sharedSecret = new Uint8Array(32 * 4)
        } else {
            sharedSecret = new Uint8Array(32 * 5)
        }

        // As specified in X3DH spec secion 22, the first 32 bytes are
        // 0xFF for curve25519 (https://signal.org/docs/specifications/x3dh/#cryptographic-notation)
        for (let i = 0; i < 32; i++) {
            sharedSecret[i] = 0xff
        }

        if (!SPKb) {
            this.logger.sendEvent(`1-1-create-sender-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'startSessionAsInitiator',
                error: `theirSignedPubKey is undefined. Cannot proceed with ECDHE`,
            })
            throw new Error(`theirSignedPubKey is undefined. Cannot proceed with ECDHE`)
        }

        // X3DH Section 3.3. https://signal.org/docs/specifications/x3dh/
        // We'll handle the possible one-time prekey below
        const ecRes = await Promise.all([
            Internal.crypto.ECDHE(SPKb, IKa.privKey),
            Internal.crypto.ECDHE(IKb, EKa.privKey),
            Internal.crypto.ECDHE(SPKb, EKa.privKey),
        ])

        sharedSecret.set(new Uint8Array(ecRes[0]), 32)
        sharedSecret.set(new Uint8Array(ecRes[1]), 32 * 2)

        sharedSecret.set(new Uint8Array(ecRes[2]), 32 * 3)

        if (OPKb !== undefined) {
            const ecRes4 = await Internal.crypto.ECDHE(OPKb, EKa.privKey)
            sharedSecret.set(new Uint8Array(ecRes4), 32 * 4)
        }

        const masterKey = await Internal.HKDF(uint8ArrayToArrayBuffer(sharedSecret), new ArrayBuffer(32), 'WhisperText')

        const session: SessionType = {
            registrationId: registrationId,
            currentRatchet: {
                rootKey: masterKey[0],
                lastRemoteEphemeralKey: SPKb,
                previousCounter: 0,
            },
            indexInfo: {
                remoteIdentityKey: IKb,
                closed: -1,
            },
            oldRatchetList: [],
            chains: {},
        }

        // We're initiating so we go ahead and set our first sending ephemeral key now,
        // otherwise we figure it out when we first maybeStepRatchet with the remote's ephemeral key

        session.indexInfo.baseKey = EKa.pubKey
        session.indexInfo.baseKeyType = BaseKeyType.OURS
        const ourSendingEphemeralKey = await Internal.crypto.createKeyPair()
        session.currentRatchet.ephemeralKeyPair = ourSendingEphemeralKey

        await this.calculateSendingRatchet(session, SPKb)

        this.logger.sendEvent(`1-1-create-sender-session:address=${this.remoteAddress.toString()}`, {
            functionName: 'startSessionAsInitiator',
            info: `Successfully created session and sending ratchet`,
        })

        return session
    }

    // Arguments map to the X3DH spec: https://signal.org/docs/specifications/x3dh/#keys
    // We are Bob now.
    startSessionWthPreKeyMessage = async (
        OPKb: KeyPairType<ArrayBuffer> | undefined,
        SPKb: KeyPairType<ArrayBuffer>,
        message: PreKeyWhisperMessage
    ): Promise<SessionType> => {
        const IKb = await this.storage.getIdentityKeyPair()
        const IKa = message.identityKey
        const EKa = message.baseKey

        if (!IKb) {
            this.logger.sendEvent(`1-1-create-receiver-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'startSessionWthPreKeyMessage',
                error: `No identity key. Cannot initiate session.`,
            })
            throw new Error(`No identity key. Cannot initiate session.`)
        }

        let sharedSecret: Uint8Array
        if (!OPKb) {
            sharedSecret = new Uint8Array(32 * 4)
        } else {
            sharedSecret = new Uint8Array(32 * 5)
        }

        // As specified in X3DH spec secion 22, the first 32 bytes are
        // 0xFF for curve25519 (https://signal.org/docs/specifications/x3dh/#cryptographic-notation)
        for (let i = 0; i < 32; i++) {
            sharedSecret[i] = 0xff
        }

        // X3DH Section 3.3. https://signal.org/docs/specifications/x3dh/
        // We'll handle the possible one-time prekey below
        const ecRes = await Promise.all([
            Internal.crypto.ECDHE(IKa, SPKb.privKey),
            Internal.crypto.ECDHE(EKa, IKb.privKey),
            Internal.crypto.ECDHE(EKa, SPKb.privKey),
        ])

        sharedSecret.set(new Uint8Array(ecRes[0]), 32)
        sharedSecret.set(new Uint8Array(ecRes[1]), 32 * 2)
        sharedSecret.set(new Uint8Array(ecRes[2]), 32 * 3)

        if (OPKb) {
            const ecRes4 = await Internal.crypto.ECDHE(EKa, OPKb.privKey)
            sharedSecret.set(new Uint8Array(ecRes4), 32 * 4)
        }

        const masterKey = await Internal.HKDF(uint8ArrayToArrayBuffer(sharedSecret), new ArrayBuffer(32), 'WhisperText')

        const session: SessionType = {
            registrationId: message.registrationId,
            currentRatchet: {
                rootKey: masterKey[0],
                lastRemoteEphemeralKey: EKa,
                previousCounter: 0,
            },
            indexInfo: {
                remoteIdentityKey: IKa,
                closed: -1,
            },
            oldRatchetList: [],
            chains: {},
        }

        // If we're initiating we go ahead and set our first sending ephemeral key now,
        // otherwise we figure it out when we first maybeStepRatchet with the remote's ephemeral key

        session.indexInfo.baseKey = EKa
        session.indexInfo.baseKeyType = BaseKeyType.THEIRS
        session.currentRatchet.ephemeralKeyPair = SPKb

        this.logger.sendEvent(`1-1-create-receiver-session:address=${this.remoteAddress.toString()}`, {
            functionName: 'startSessionWthPreKeyMessage',
            info: `Successfully created receiver session.`,
            hasPreKey: !!OPKb,
        })

        return session
    }

    async calculateSendingRatchet(session: SessionType, remoteKey: ArrayBuffer): Promise<void> {
        const ratchet = session.currentRatchet
        if (!ratchet.ephemeralKeyPair) {
            this.logger.sendEvent(`1-1-create-sender-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'calculateSendingRatchet',
                error: `Invalid ratchet - ephemeral key pair is missing`,
            })
            throw new Error(`Invalid ratchet - ephemeral key pair is missing`)
        }

        const ephPrivKey = ratchet.ephemeralKeyPair.privKey
        const rootKey = ratchet.rootKey
        const ephPubKey = base64.fromByteArray(new Uint8Array(ratchet.ephemeralKeyPair.pubKey))
        if (!(ephPrivKey && ephPubKey && rootKey)) {
            this.logger.sendEvent(`1-1-create-sender-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'calculateSendingRatchet',
                error: `Missing key, cannot calculate sending ratchet`,
            })
            throw new Error(`Missing key, cannot calculate sending ratchet`)
        }
        const sharedSecret = await Internal.crypto.ECDHE(remoteKey, ephPrivKey)
        const masterKey = await Internal.HKDF(sharedSecret, rootKey, 'WhisperRatchet')

        session.chains[ephPubKey] = {
            messageKeys: {},
            chainKey: { counter: -1, key: masterKey[1] },
            chainType: ChainType.SENDING,
        }
        ratchet.rootKey = masterKey[0]
    }

    async processPreKey(device: DeviceType): Promise<SessionType> {
        // return this.processPreKeyJob(device)
        const runJob = async () => {
            return await this.processPreKeyJob(device)
        }
        return SessionLock.queueJob(this.remoteAddress.toString(), runJob)
    }

    async processV3(record: SessionRecord, message: PreKeyWhisperMessage): Promise<number | void> {
        const trusted = await this.storage.isTrustedIdentity(
            this.remoteAddress.toString(),
            uint8ArrayToArrayBuffer(message.identityKey),
            Direction.RECEIVING
        )

        if (!trusted) {
            this.logger.sendEvent(`1-1-create-receiver-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'processV3',
                error: `Unknown identity key: ${uint8ArrayToArrayBuffer(message.identityKey)}`,
            })
            throw new Error(`Unknown identity key: ${uint8ArrayToArrayBuffer(message.identityKey)}`)
        }

        // session already created and the preKey is mostly deleted
        if (record.getSessionByBaseKey(message.baseKey)) {
            this.logger.sendEvent(`1-1-create-receiver-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'processV3',
                info: `Found a session created already with baseKey: ${arrayBufferToString(
                    message.baseKey
                )} and the preKey used ${message.preKeyId}`,
            })
            return message.preKeyId
        }

        const [preKeyPair, signedPreKeyPair] = await Promise.all([
            this.storage.loadPreKey(message.preKeyId),
            this.storage.loadSignedPreKey(message.signedPreKeyId),
        ])

        const session = record.getOpenSession()

        // this assumes the signedPreKey will be deleted, but we don't delete it, so this case shouldn't happen
        // so we will fail if happened
        if (signedPreKeyPair === undefined) {
            // Session may or may not be the right one, but if its not, we
            // can't do anything about it ...fall through and let
            // decryptWhisperMessage handle that case
            if (session !== undefined && session.currentRatchet !== undefined) {
                this.logger.sendEvent(`1-1-create-receiver-session:address=${this.remoteAddress.toString()}`, {
                    functionName: 'processV3',
                    error: `There is no signed preKey locally, but there is open session, so we hope it's it`,
                })
                return
            } else {
                this.logger.sendEvent(`1-1-create-receiver-session:address=${this.remoteAddress.toString()}`, {
                    functionName: 'processV3',
                    error: `Missing Signed PreKey for PreKeyWhisperMessage`,
                })
                throw new Error('Missing Signed PreKey for PreKeyWhisperMessage')
            }
        }

        if (message.preKeyId && !preKeyPair) {
            this.logger.sendEvent(`1-1-create-receiver-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'processV3',
                error: `Session created with a OTK and the key doesn't exist: ${message.preKeyId}`,
            })
            throw new Error("Session created with a OTK and the key doesn't exist")
        }

        if (session !== undefined) {
            record.archiveCurrentState()
        }

        const new_session = await this.startSessionWthPreKeyMessage(preKeyPair, signedPreKeyPair, message)
        record.updateSessionState(new_session)
        await this.storage.saveIdentity(this.remoteAddress.toString(), uint8ArrayToArrayBuffer(message.identityKey))

        return message.preKeyId
    }
}
