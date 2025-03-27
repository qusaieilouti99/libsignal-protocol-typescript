import { StorageType, Direction, LoggerType } from './types'
import { Chain, ChainType, SessionType } from './session-types'
import { SignalProtocolAddress } from './signal-protocol-address'
import { PreKeyWhisperMessage, WhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts'
import * as base64 from 'base64-js'
import * as util from './helpers'
import * as Internal from './internal'

import { SessionRecord } from './session-record'
import { SessionLock } from './session-lock'
import { SessionBuilder } from './session-builder'
import { uint8ArrayToArrayBuffer } from './helpers'

export interface MessageType {
    type: number
    body?: string
    registrationId?: number
}

export class SessionCipher {
    storage: StorageType
    remoteAddress: SignalProtocolAddress
    logger: LoggerType

    constructor(storage: StorageType, remoteAddress: SignalProtocolAddress | string, logger: LoggerType) {
        this.storage = storage
        this.logger = logger
        this.remoteAddress =
            typeof remoteAddress === 'string' ? SignalProtocolAddress.fromString(remoteAddress) : remoteAddress
    }

    async getRecord(encodedNumber: string): Promise<SessionRecord | undefined> {
        const serialized = await this.storage.loadSession(encodedNumber)
        if (serialized === undefined) {
            return undefined
        }
        return SessionRecord.deserialize(serialized)
    }

    encrypt(buffer: ArrayBuffer): Promise<MessageType> {
        return SessionLock.queueJob(this.remoteAddress.toString(), () => this.encryptJob(buffer))
    }

    private encryptJob = async (buffer: ArrayBuffer) => {
        if (!(buffer instanceof ArrayBuffer)) {
            throw new Error('Expected buffer to be an ArrayBuffer')
        }

        const address = this.remoteAddress.toString()
        const msg = WhisperMessage.fromJSON({})
        const [ourIdentityKey, myRegistrationId, record] = await this.loadKeysAndRecord(address)

        if (!record) {
            this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'encryptJob',
                error: `No record found to encrypt with`,
            })
            throw new Error('No record for ' + address)
        }

        if (!ourIdentityKey) {
            this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'encryptJob',
                error: `No identity key locally for me`,
            })
            throw new Error(`cannot encrypt without identity key`)
        }
        // if (!myRegistrationId) {
        //     throw new Error(`cannot encrypt without registration id`)
        // }

        const { session, chain } = await this.prepareChain(address, record, msg)

        const keys = await Internal.HKDF(
            chain.messageKeys[chain.chainKey.counter],
            new ArrayBuffer(32),
            'WhisperMessageKeys'
        )

        this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
            functionName: 'encryptJob',
            info: `generated key for counter ${chain.chainKey.counter}`,
        })

        delete chain.messageKeys[chain.chainKey.counter]
        msg.counter = chain.chainKey.counter
        msg.previousCounter = session.currentRatchet.previousCounter

        const ciphertext = await Internal.crypto.encrypt(keys[0], buffer, keys[2].slice(0, 16))
        msg.ciphertext = new Uint8Array(ciphertext)
        const encodedMsg = WhisperMessage.encode(msg).finish()

        const macInput = new Uint8Array(encodedMsg.byteLength + 33 * 2 + 1)
        macInput.set(new Uint8Array(ourIdentityKey.pubKey))
        macInput.set(new Uint8Array(session.indexInfo.remoteIdentityKey), 33)
        macInput[33 * 2] = (3 << 4) | 3
        macInput.set(new Uint8Array(encodedMsg), 33 * 2 + 1)

        const mac = await Internal.crypto.sign(keys[1], macInput.buffer)

        const encodedMsgWithMAC = new Uint8Array(encodedMsg.byteLength + 9)
        encodedMsgWithMAC[0] = (3 << 4) | 3
        encodedMsgWithMAC.set(new Uint8Array(encodedMsg), 1)
        encodedMsgWithMAC.set(new Uint8Array(mac, 0, 8), encodedMsg.byteLength + 1)

        const trusted = await this.storage.isTrustedIdentity(
            this.remoteAddress.toString(),
            session.indexInfo.remoteIdentityKey,
            Direction.SENDING
        )

        if (!trusted) {
            this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'encryptJob',
                error: `Identity key changed`,
            })
            throw new Error('Identity key changed')
        }

        this.storage.saveIdentity(this.remoteAddress.toString(), session.indexInfo.remoteIdentityKey)
        record.updateSessionState(session)
        await this.storage.storeSession(address, record.serialize())

        this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
            functionName: 'encryptJob',
            info: `successfully encrypted and generated mac and deleted key for counter ${chain.chainKey.counter}`,
            msgCounter: chain.chainKey.counter,
            msgPrevCounter: msg.previousCounter,
            ourIdentityPub: base64.fromByteArray(new Uint8Array(ourIdentityKey.pubKey)),
            remIdentityPub: base64.fromByteArray(new Uint8Array(session.indexInfo.remoteIdentityKey)),
            hasPreKey: !!session.pendingPreKey,
        })

        if (session.pendingPreKey !== undefined) {
            const preKeyMsg = PreKeyWhisperMessage.fromJSON({})
            preKeyMsg.identityKey = new Uint8Array(ourIdentityKey.pubKey)

            // TODO: for some test vectors there is no registration id. Why?
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            preKeyMsg.registrationId = myRegistrationId!

            preKeyMsg.baseKey = new Uint8Array(session.pendingPreKey.baseKey)
            if (session.pendingPreKey.preKeyId) {
                preKeyMsg.preKeyId = session.pendingPreKey.preKeyId
            }
            preKeyMsg.signedPreKeyId = session.pendingPreKey.signedKeyId

            preKeyMsg.message = encodedMsgWithMAC
            const encodedPreKeyMsg = PreKeyWhisperMessage.encode(preKeyMsg).finish()
            const result = String.fromCharCode((3 << 4) | 3) + util.uint8ArrayToString(encodedPreKeyMsg)

            this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'encryptJob',
                info: `successfully encrypted and we will return pre key msg ${chain.chainKey.counter}`,
                preKeyMsg: result,
            })
            return {
                type: 3,
                body: result,
                registrationId: session.registrationId,
            }
        } else {
            this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'encryptJob',
                info: `successfully encrypted and we will return normal msg ${chain.chainKey.counter}`,
            })
            return {
                type: 1,
                body: util.uint8ArrayToString(encodedMsgWithMAC),
                registrationId: session.registrationId,
            }
        }
    }

    private loadKeysAndRecord = (address: string) => {
        return Promise.all([
            this.storage.getIdentityKeyPair(),
            this.storage.getLocalRegistrationId(),
            this.getRecord(address),
        ])
    }

    private prepareChain = async (address: string, record: SessionRecord, msg: WhisperMessage) => {
        const session = record.getOpenSession()
        if (!session) {
            this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'prepareChain',
                error: `No session to encrypt message`,
            })
            throw new Error('No session to encrypt message for ' + address)
        }

        if (!session.currentRatchet.ephemeralKeyPair) {
            this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'prepareChain',
                error: `ratchet missing ephemeralKeyPair`,
            })
            throw new Error(`ratchet missing ephemeralKeyPair`)
        }

        msg.ephemeralKey = new Uint8Array(session.currentRatchet.ephemeralKeyPair.pubKey)
        const searchKey = base64.fromByteArray(msg.ephemeralKey)

        const chain = session.chains[searchKey]
        if (chain?.chainType === ChainType.RECEIVING) {
            this.logger.sendEvent(`1-1-encrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'prepareChain',
                error: `Tried to encrypt on a receiving chain`,
            })
            throw new Error('Tried to encrypt on a receiving chain')
        }

        await this.fillMessageKeys(chain, chain.chainKey.counter + 1)
        return { session, chain }
    }

    private fillMessageKeys = async (chain: Chain<ArrayBuffer>, counter: number): Promise<void> => {
        if (chain.chainKey.counter >= counter) {
            return Promise.resolve() // Already calculated
        }

        if (chain.chainKey.key === undefined) {
            this.logger.sendEvent(`1-1-encrypt&decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'fillMessageKeys',
                error: `Got invalid request to extend chain after it was already closed for counter:${counter}`,
            })
            throw new Error('Got invalid request to extend chain after it was already closed')
        }

        const ckey = chain.chainKey.key
        if (!ckey) {
            this.logger.sendEvent(`1-1-encrypt&decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'fillMessageKeys',
                error: `chain key is missing for counter:${counter}`,
            })
            throw new Error(`chain key is missing`)
        }

        // Compute KDF_CK as described in X3DH specification
        const byteArray = new Uint8Array(1)
        byteArray[0] = 1
        const mac = await Internal.crypto.sign(ckey, byteArray.buffer)
        byteArray[0] = 2
        const key = await Internal.crypto.sign(ckey, byteArray.buffer)

        chain.messageKeys[chain.chainKey.counter + 1] = mac
        chain.chainKey.key = key
        chain.chainKey.counter += 1

        this.logger.sendEvent(`1-1-encrypt&decrypt:address=${this.remoteAddress.toString()}`, {
            functionName: 'fillMessageKeys',
            info: `Successfully created message key for counter: ${chain.chainKey.counter}`,
        })
        await this.fillMessageKeys(chain, counter)
    }

    private async calculateRatchet(session: SessionType, remoteKey: ArrayBuffer, sending: boolean) {
        const ratchet = session.currentRatchet

        if (!ratchet.ephemeralKeyPair) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'calculateRatchet',
                error: `currentRatchet has no ephemeral key. Cannot calculateRatchet.`,
            })
            throw new Error(`currentRatchet has no ephemeral key. Cannot calculateRatchet.`)
        }
        const sharedSecret = await Internal.crypto.ECDHE(remoteKey, ratchet.ephemeralKeyPair.privKey)
        const masterKey = await Internal.HKDF(sharedSecret, ratchet.rootKey, 'WhisperRatchet')
        let ephemeralPublicKey
        if (sending) {
            ephemeralPublicKey = ratchet.ephemeralKeyPair.pubKey
        } else {
            ephemeralPublicKey = remoteKey
        }
        session.chains[base64.fromByteArray(new Uint8Array(ephemeralPublicKey))] = {
            messageKeys: {},
            chainKey: { counter: -1, key: masterKey[1] },
            chainType: sending ? ChainType.SENDING : ChainType.RECEIVING,
        }
        ratchet.rootKey = masterKey[0]

        this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
            functionName: 'calculateRatchet',
            info: `Creating a ${sending ? 'sending' : 'receiving'} ratchet`,
        })
    }

    async decryptPreKeyWhisperMessage(
        buff: string | ArrayBuffer,
        encoding?: string,
        textId = ''
    ): Promise<ArrayBuffer> {
        encoding = encoding || 'binary'
        if (encoding !== 'binary') {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'decryptPreKeyWhisperMessage',
                error: `unsupported encoding: ${encoding}`,
            })
            throw new Error(`unsupported encoding: ${encoding}`)
        }

        const buffer = typeof buff === 'string' ? util.binaryStringToArrayBuffer(buff) : buff
        const view = new Uint8Array(buffer)
        const version = view[0]
        const messageData = view.slice(1)

        if ((version & 0xf) > 3 || version >> 4 < 3) {
            // min version > 3 or max version < 3
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'decryptPreKeyWhisperMessage',
                error: `Incompatible version number on PreKeyWhisperMessage`,
            })
            throw new Error('Incompatible version number on PreKeyWhisperMessage')
        }

        const address = this.remoteAddress.toString()
        const job = async () => {
            let record = await this.getRecord(address)
            const preKeyProto = PreKeyWhisperMessage.decode(messageData)
            if (!record) {
                if (preKeyProto.registrationId === undefined) {
                    this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                        functionName: 'decryptPreKeyWhisperMessage',
                        error: `No registrationId`,
                        signedPreKeyId: preKeyProto.signedPreKeyId,
                        preKeyId: preKeyProto.preKeyId,
                    })
                    throw new Error('No registrationId')
                }
                record = new SessionRecord() // (preKeyProto.registrationId)???
            }
            const builder = new SessionBuilder(this.storage, this.remoteAddress, this.logger)

            // isTrustedIdentity is called within processV3, no need to call it here
            const preKeyId = await builder.processV3(record, preKeyProto)
            const session = record.getSessionByBaseKey(uint8ArrayToArrayBuffer(preKeyProto.baseKey))
            if (!session) {
                this.logger.sendEvent(`1-1-create-receiver-session:address=${this.remoteAddress.toString()}`, {
                    functionName: 'decryptPreKeyWhisperMessage',
                    error: `unable to find session for base key ${base64.fromByteArray(preKeyProto.baseKey)}, ${
                        preKeyProto.baseKey.byteLength
                    } and the preKeyId is ${preKeyId}`,
                })
                throw new Error(
                    `unable to find session for base key ${base64.fromByteArray(preKeyProto.baseKey)}, ${
                        preKeyProto.baseKey.byteLength
                    }`
                )
            }
            const plaintext = await this.doDecryptWhisperMessage(preKeyProto.message, session, textId)
            record.updateSessionState(session)
            await this.storage.storeSession(address, record.serialize())
            // to add the user and device record when creating a session
            this.storage.addDevice(this.remoteAddress.getName(), this.remoteAddress.getDeviceId())
            if (preKeyId !== undefined && preKeyId !== null) {
                await this.storage.removePreKey(preKeyId)
            }

            this.logger.sendEvent(`1-1-create-receiver-session:address=${this.remoteAddress.toString()}`, {
                functionName: 'decryptPreKeyWhisperMessage',
                info: `message decrypted successfully and the session stored and the device added and ${
                    preKeyId ? `the preKey ${preKeyId} deleted` : ''
                }}`,
            })
            return plaintext
        }

        return SessionLock.queueJob(address, job)
    }

    async decryptWithSessionList(
        buffer: ArrayBuffer,
        sessionList: SessionType[],
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        errors: any[],
        textId = ''
    ): Promise<{ plaintext: ArrayBuffer; session: SessionType }> {
        // Iterate recursively through the list, attempting to decrypt
        // using each one at a time. Stop and return the result if we get
        // a valid result
        if (sessionList.length === 0) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'decryptWithSessionList',
                error: `Empty session list`,
            })
            throw new Error('Empty session list')
        }

        for (const session of sessionList) {
            try {
                const plaintext = await this.doDecryptWhisperMessage(buffer, session, textId)

                return { plaintext: plaintext, session: session }
            } catch (e: any) {
                this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                    functionName: 'decryptWithSessionList',
                    error: `Failed to decrypt with this session and the error is ${e.toString()}`,
                })
                if ((e as Error).name === 'MessageCounterError') {
                    throw e
                }

                errors.push(e)
            }
        }

        this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
            functionName: 'decryptWithSessionList',
            error: `Failed to decrypt with any session and the error is ${errors[0].toString()}`,
        })

        throw new Error(errors[0])
    }

    decryptWhisperMessage(buff: string | ArrayBuffer, encoding?: string, textId = ''): Promise<ArrayBuffer> {
        encoding = encoding || 'binary'
        if (encoding !== 'binary') {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'decryptWhisperMessage',
                error: `unsupported encoding: ${encoding}`,
            })
            throw new Error(`unsupported encoding: ${encoding}`)
        }

        const buffer = typeof buff === 'string' ? util.binaryStringToArrayBuffer(buff) : buff
        const address = this.remoteAddress.toString()
        const job = async () => {
            const record = await this.getRecord(address)
            if (!record) {
                this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                    functionName: 'decryptWhisperMessage',
                    error: `No record for device`,
                })
                throw new Error('No record for device ' + address)
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const errors: any[] = []
            const result = await this.decryptWithSessionList(buffer, record.getSessions(), errors, textId)

            // if the correct session for decrypting this is closed, we make it open
            if (result.session.indexInfo.baseKey !== record.getOpenSession()?.indexInfo.baseKey) {
                record.archiveCurrentState()
                record.promoteState(result.session)
            }

            const trusted = await this.storage.isTrustedIdentity(
                this.remoteAddress.toString(),
                result.session.indexInfo.remoteIdentityKey,
                Direction.RECEIVING
            )

            if (!trusted) {
                this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                    functionName: 'decryptWhisperMessage',
                    error: `Identity key changed`,
                })
                throw new Error('Identity key changed')
            }

            await this.storage.saveIdentity(address, result.session.indexInfo.remoteIdentityKey)
            record.updateSessionState(result.session)
            await this.storage.storeSession(address, record.serialize())

            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'decryptWhisperMessage',
                info: `Decrypt successfully and storing the session for ${textId}`,
            })

            return result.plaintext
        }

        return SessionLock.queueJob(address, job)
    }

    async doDecryptWhisperMessage(messageBytes: ArrayBuffer, session: SessionType, textId = ''): Promise<ArrayBuffer> {
        const version = new Uint8Array(messageBytes)[0]
        if ((version & 0xf) > 3 || version >> 4 < 3) {
            // min version > 3 or max version < 3
            throw new Error('Incompatible version number on WhisperMessage ' + version)
        }
        const messageProto = messageBytes.slice(1, messageBytes.byteLength - 8)
        const mac = messageBytes.slice(messageBytes.byteLength - 8, messageBytes.byteLength)

        const message = WhisperMessage.decode(new Uint8Array(messageProto))
        const remoteEphemeralKey = uint8ArrayToArrayBuffer(message.ephemeralKey)

        if (session === undefined) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'doDecryptWhisperMessage',
                error: `No session found to decrypt message from, this is mostly because the signedPreKey was missing`,
            })
            return Promise.reject(
                new Error('No session found to decrypt message from ' + this.remoteAddress.toString())
            )
        }
        if (session.indexInfo.closed != -1) {
            //  console.log('decrypting message for closed session')
        }

        await this.maybeStepRatchet(session, remoteEphemeralKey, message.previousCounter)

        const chain = session.chains[base64.fromByteArray(message.ephemeralKey)]
        if (!chain) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'doDecryptWhisperMessage',
                error: `no chain found for key ${base64.fromByteArray(message.ephemeralKey)}`,
            })
            throw new Error(`no chain found for key ${base64.fromByteArray(message.ephemeralKey)}`)
        }

        if (chain?.chainType === ChainType.SENDING) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'doDecryptWhisperMessage',
                error: `Tried to decrypt on a sending chain`,
            })
            throw new Error('Tried to decrypt on a sending chain')
        }

        await this.fillMessageKeys(chain, message.counter)

        const messageKey = chain.messageKeys[message.counter]
        if (messageKey === undefined) {
            const alreadyDecryptedText = await this.storage.getDecryptedText(textId)
            if (alreadyDecryptedText) {
                this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                    functionName: 'doDecryptWhisperMessage',
                    info: `Fallback to already decrypted and stored message for ${textId} and msgCounter ${message.counter}`,
                })
                return alreadyDecryptedText
            }

            const e = new Error('Message key not found. The counter was repeated or the key was not filled.')
            e.name = 'MessageCounterError'
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'doDecryptWhisperMessage',
                error: `'Message key not found. The counter was repeated or the key was not filled.`,
            })
            throw e
        }

        const keys = await Internal.HKDF(messageKey, new ArrayBuffer(32), 'WhisperMessageKeys')

        const ourIdentityKey = await this.storage.getIdentityKeyPair()
        if (!ourIdentityKey) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'doDecryptWhisperMessage',
                error: `Our identity key is missing. Cannot decrypt.`,
            })
            throw new Error(`Our identity key is missing. Cannot decrypt.`)
        }

        const macInput = new Uint8Array(messageProto.byteLength + 33 * 2 + 1)
        macInput.set(new Uint8Array(session.indexInfo.remoteIdentityKey))
        macInput.set(new Uint8Array(ourIdentityKey.pubKey), 33)
        macInput[33 * 2] = (3 << 4) | 3
        macInput.set(new Uint8Array(messageProto), 33 * 2 + 1)

        this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
            functionName: 'doDecryptWhisperMessage',
            info: `Verifying mac for ${textId} and msgCounter ${message.counter}`,
        })

        try {
            await Internal.verifyMAC(macInput.buffer, keys[1], mac, 8)
        } catch (e: any) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'doDecryptWhisperMessage',
                error: `Verifying mac failed for ${textId} and msgCounter ${message.counter} and error ${e.toString()}`,
            })
            throw e
        }

        let plaintext: ArrayBuffer
        try {
            plaintext = await Internal.crypto.decrypt(
                keys[0],
                uint8ArrayToArrayBuffer(message.ciphertext),
                keys[2].slice(0, 16)
            )
        } catch (e: any) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'doDecryptWhisperMessage',
                error: `Decrypting failed for ${textId} and msgCounter ${message.counter} and error ${e.toString()}`,
            })
            throw e
        }

        // store the decrypted message, so if a failure happened before its being used, we can reuse it.
        await this.storage.storeDecryptedText(textId, plaintext)

        // after successfully decrypting and storing the decrypted text, we remove the key that we used.
        delete chain.messageKeys[message.counter]

        // if there still be a pending key, remove it because the session is being used successfully
        delete session.pendingPreKey

        this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
            functionName: 'doDecryptWhisperMessage',
            info: `Decrypting succeed for ${textId} and msgCounter ${message.counter}`,
        })

        return plaintext
    }

    async maybeStepRatchet(session: SessionType, remoteKey: ArrayBuffer, previousCounter: number): Promise<void> {
        const remoteKeyString = base64.fromByteArray(new Uint8Array(remoteKey))
        if (session.chains[remoteKeyString] !== undefined) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'maybeStepRatchet',
                info: `No need to step ratchet`,
            })
            return Promise.resolve()
        }

        const ratchet = session.currentRatchet
        if (!ratchet.ephemeralKeyPair) {
            this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                functionName: 'maybeStepRatchet',
                error: `attempting to step ratchet without ephemeral key`,
            })
            throw new Error(`attempting to step reatchet without ephemeral key`)
        }

        const previousReceivingRatchet =
            session.chains[base64.fromByteArray(new Uint8Array(ratchet.lastRemoteEphemeralKey))]
        if (previousReceivingRatchet !== undefined) {
            await this.fillMessageKeys(previousReceivingRatchet, previousCounter).then(() => {
                delete previousReceivingRatchet.chainKey.key
                session.oldRatchetList[session.oldRatchetList.length] = {
                    added: Date.now(),
                    ephemeralKey: ratchet.lastRemoteEphemeralKey,
                }
                this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
                    functionName: 'maybeStepRatchet',
                    info: `Moving a ratchet to oldRatchetList`,
                })
            })
        }

        await this.calculateRatchet(session, remoteKey, false)

        // here we delete the chain for the previous sending ratchet, no need to keep
        const previousSendingRatchetKey = base64.fromByteArray(new Uint8Array(ratchet.ephemeralKeyPair.pubKey))
        if (session.chains[previousSendingRatchetKey] !== undefined) {
            ratchet.previousCounter = session.chains[previousSendingRatchetKey].chainKey.counter
            delete session.chains[previousSendingRatchetKey]
        }

        ratchet.ephemeralKeyPair = await Internal.crypto.createKeyPair()
        await this.calculateRatchet(session, remoteKey, true)
        ratchet.lastRemoteEphemeralKey = remoteKey

        this.logger.sendEvent(`1-1-decrypt:address=${this.remoteAddress.toString()}`, {
            functionName: 'maybeStepRatchet',
            info: `Successfully stepped sending and receiving ratchet`,
        })
    }

    /////////////////////////////////////////
    // session management and storage access
    getRemoteRegistrationId(): Promise<number | undefined> {
        return SessionLock.queueJob(this.remoteAddress.toString(), async () => {
            const record = await this.getRecord(this.remoteAddress.toString())
            if (record === undefined) {
                return undefined
            }
            const openSession = record.getOpenSession()
            if (openSession === undefined) {
                return undefined
            }
            return openSession.registrationId
        })
    }

    hasOpenSession(): Promise<boolean> {
        const job = async () => {
            const record = await this.getRecord(this.remoteAddress.toString())
            if (record === undefined) {
                return false
            }
            return record.haveOpenSession()
        }
        return SessionLock.queueJob(this.remoteAddress.toString(), job)
    }
    closeOpenSessionForDevice(): Promise<void> {
        const address = this.remoteAddress.toString()
        const job = async () => {
            const record = await this.getRecord(this.remoteAddress.toString())
            if (record === undefined || record.getOpenSession() === undefined) {
                return
            }

            record.archiveCurrentState()
            return this.storage.storeSession(address, record.serialize())
        }

        return SessionLock.queueJob(address, job)
    }
    deleteAllSessionsForDevice(): Promise<void> {
        // Used in session reset scenarios, where we really need to delete
        const address = this.remoteAddress.toString()
        const job = async () => {
            const record = await this.getRecord(this.remoteAddress.toString())
            if (record === undefined) {
                return
            }

            record.deleteAllSessions()
            return this.storage.storeSession(address, record.serialize())
        }
        return SessionLock.queueJob(address, job)
    }
}
