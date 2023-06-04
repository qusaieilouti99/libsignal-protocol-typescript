/**/

// create chainKey
// generate a signatureKey keypair that will be used for signing the messages. (priv,pub)

// send this to all the group members using the 1-1 pairwise channel { chainKey, signatureKey.publicKey }

// to send a message you encrypt the message using the chainKey then sign the cipherText using the signatureKey.privateKey

// we send {cipherText, signature}

// for the next messages we do the same, but before we derive a new chainKey from the existing one.

// RECEIVER
// he receives the { chainKey, signatureKey.publicKey } senderKeyMessage
// he stores this key.

// when he receives a new message {cipherText, signature} from the sender he verifies the signature with the signatureKey.publicKey

// if verifySig(signature,signatureKey.publicKey) === cipherText then valid

// then he decrypts the message using chainKey and step the ratchet

// senderKeys{groupId} => [{chainKey,publicKey,chains}]

// session{groupId}{address} = {
//
//
//
// }

import * as util from './helpers'
import { SessionLock } from './session-lock'
import { Chain, ChainType, GroupSessionType, LocalSenderKey, SenderKey } from './session-types'
import { SignalProtocolAddressType, StorageType } from './types'
import * as Internal from './internal'
import * as base64 from 'base64-js'
import { GroupWhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts'
import { GroupSessionRecord } from './group-session-record'

export class GroupCipher {
    address: SignalProtocolAddressType
    storage: StorageType

    constructor(storage: StorageType, address: SignalProtocolAddressType) {
        this.address = address
        this.storage = storage
    }

    encrypt(buffer: ArrayBuffer): Promise<{ cipherText: string; senderKeyVersion: number }> {
        return SessionLock.queueJobForNumber(this.address.toString(), () => this.encryptJob(buffer))
    }

    createSenderSession(version: number): Promise<{ senderKey: SenderKey; session: string }> {
        return SessionLock.queueJobForNumber(this.address.toString(), () => this.createSenderSessionJob(version))
    }

    createOrUpdateReceiverSession(senderKey: SenderKey): Promise<void> {
        return SessionLock.queueJobForNumber(this.address.toString(), () =>
            this.createOrUpdateReceiverSessionJob(senderKey)
        )
    }

    resetSenderSession(version: number): Promise<{ senderKey: SenderKey; session: string }> {
        return SessionLock.queueJobForNumber(this.address.toString(), () => this.resetSenderSessionJob(version))
    }

    decrypt(buff: string | ArrayBuffer, encoding?: string): Promise<ArrayBuffer> {
        return SessionLock.queueJobForNumber(this.address.toString(), () => this.decryptJob(buff, encoding))
    }

    private async decryptJob(buff: string | ArrayBuffer, encoding?: string): Promise<ArrayBuffer> {
        encoding = encoding || 'binary'
        if (encoding !== 'binary') {
            throw new Error(`unsupported encoding: ${encoding}`)
        }
        const buffer = typeof buff === 'string' ? util.binaryStringToArrayBuffer(buff) : buff
        const address = this.address.toString()

        const message = GroupWhisperMessage.decode(new Uint8Array(buffer))

        await Internal.crypto.Ed25519Verify(
            util.uint8ArrayToArrayBuffer(message.signaturePublicKey),
            util.uint8ArrayToArrayBuffer(message.ciphertext),
            util.uint8ArrayToArrayBuffer(message.signature)
        )

        const session = await this.getSession(address)
        if (!session) {
            const e = new Error('No record for device ' + address)
            e.name = 'NO_SESSION'
            throw e
        }

        const chain = session.chains[base64.fromByteArray(message.signaturePublicKey)]
        if (!chain) {
            const e = new Error('no chain found for key ')
            e.name = 'NO_CHAIN'
            throw e
        }

        if (chain?.chainType === ChainType.SENDING) {
            throw new Error('Tried to decrypt on a sending chain')
        }

        await this.fillMessageKeys(chain, message.counter)

        const messageKey = chain.messageKeys[message.counter]
        if (messageKey === undefined) {
            throw new Error('Message key not found. The counter was repeated or the key was not filled.')
        }

        delete chain.messageKeys[message.counter]
        const keys = await Internal.HKDF(messageKey, new ArrayBuffer(32), 'WhisperMessageKeys')

        const plaintext = await Internal.crypto.decrypt(
            keys[0],
            util.uint8ArrayToArrayBuffer(message.ciphertext),
            keys[2].slice(0, 16)
        )

        GroupSessionRecord.removeOldChains(session)
        const ser = GroupSessionRecord.serializeGroupSession(session)
        await this.storage.storeSession(address, ser)
        return plaintext
    }

    private prepareChain = async (address: string, session: GroupSessionType, msg: GroupWhisperMessage) => {
        if (!session) {
            throw new Error('No session to encrypt message for ' + address)
        }

        if (!session.currentRatchet?.signaturePublicKey) {
            throw new Error(`ratchet missing signaturePublicKey`)
        }

        msg.signaturePublicKey = new Uint8Array(session.currentRatchet.signaturePublicKey)

        const chain = session.chains[base64.fromByteArray(msg.signaturePublicKey)]

        if (chain?.chainType === ChainType.RECEIVING) {
            throw new Error('Tried to encrypt on a receiving chain')
        }

        await this.fillMessageKeys(chain, chain.chainKey.counter + 1)
        return { chain }
    }

    private fillMessageKeys = async (chain: Chain<ArrayBuffer>, counter: number): Promise<void> => {
        if (chain.chainKey.counter >= counter) {
            return Promise.resolve() // Already calculated
        }

        if (chain.chainKey.key === undefined) {
            throw new Error('Got invalid request to extend chain after it was already closed')
        }

        const ckey = chain.chainKey.key
        if (!ckey) {
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
        await this.fillMessageKeys(chain, counter)
    }

    private async generateGroupSenderKey(): Promise<LocalSenderKey> {
        // this will be used for signing the cipher messages
        const signatureKeyPair = await Internal.crypto.createKeyPair()
        // this will be used for deriving the messages keys
        const chainKey = await Internal.crypto.generateAesKey()

        return { signatureKeyPair, chainKey }
    }

    private encryptJob = async (buffer: ArrayBuffer) => {
        if (!(buffer instanceof ArrayBuffer)) {
            throw new Error('Expected buffer to be an ArrayBuffer')
        }

        const address = this.address.toString()
        const msg = GroupWhisperMessage.fromJSON({})
        const session = await this.getSession(address)
        if (!session) {
            throw new Error('No session to encrypt message for ' + address)
        }

        const { chain } = await this.prepareChain(address, session, msg)

        const keys = await Internal.HKDF(
            chain.messageKeys[chain.chainKey.counter],
            new ArrayBuffer(32),
            'WhisperMessageKeys'
        )

        delete chain.messageKeys[chain.chainKey.counter]
        msg.counter = chain.chainKey.counter
        msg.previousCounter = session.currentRatchet!.previousCounter

        const ciphertext = await Internal.crypto.encrypt(keys[0], buffer, keys[2].slice(0, 16))

        const signature = await Internal.crypto.Ed25519Sign(
            session.currentRatchet!.signatureKeyPair!.privKey,
            ciphertext
        )
        msg.ciphertext = new Uint8Array(ciphertext)
        msg.signature = new Uint8Array(signature)

        const encodedMsg = GroupWhisperMessage.encode(msg).finish()

        GroupSessionRecord.removeOldChains(session)
        const ser = GroupSessionRecord.serializeGroupSession(session)
        await this.storage.storeSession(address, ser)

        // the final cipher text

        return {
            cipherText: util.uint8ArrayToString(encodedMsg),
            senderKeyVersion: session.currentRatchet!.senderKeyVersion,
        }
    }

    private createSenderSessionJob = async (version: number): Promise<{ senderKey: SenderKey; session: string }> => {
        // generate keys
        const { signatureKeyPair, chainKey } = await this.generateGroupSenderKey()
        // create the session

        const session: GroupSessionType = {
            currentRatchet: {
                senderKeyVersion: version,
                signaturePublicKey: signatureKeyPair.pubKey,
                signatureKeyPair: signatureKeyPair,
                previousCounter: 0,
            },
            oldRatchetList: [],
            chains: {
                [base64.fromByteArray(new Uint8Array(signatureKeyPair.pubKey))]: {
                    chainKey: {
                        key: chainKey,
                        counter: -1,
                    },
                    chainType: ChainType.SENDING,
                    messageKeys: {},
                },
            },
        }

        GroupSessionRecord.removeOldChains(session)
        return {
            senderKey: { signatureKey: signatureKeyPair.pubKey, chainKey, previousCounter: 0 },
            session: GroupSessionRecord.serializeGroupSession(session),
        }
    }

    private resetSenderSessionJob = async (version: number): Promise<{ senderKey: SenderKey; session: string }> => {
        // generate keys
        const { signatureKeyPair, chainKey } = await this.generateGroupSenderKey()
        // update the session
        const session = await this.getSession(this.address.toString())

        if (!session) {
            throw new Error(`No session for address ${this.address.toString()}`)
        }

        if (session.currentRatchet!.senderKeyVersion >= version) {
            throw new Error(`SenderKey with this version is already created ${this.address.toString()}`)
        }

        session.chains[base64.fromByteArray(new Uint8Array(signatureKeyPair.pubKey))] = {
            messageKeys: {},
            chainKey: { counter: -1, key: chainKey },
            chainType: ChainType.SENDING,
        }
        const ratchet = session.currentRatchet!

        const previousRatchetKey = ratchet.signaturePublicKey
        const previousRatchetKeyString = base64.fromByteArray(new Uint8Array(ratchet.signaturePublicKey))
        if (session.chains[previousRatchetKeyString] !== undefined) {
            ratchet.previousCounter = session.chains[previousRatchetKeyString].chainKey.counter
            delete session.chains[previousRatchetKeyString]
        }

        ratchet.signaturePublicKey = signatureKeyPair.pubKey
        ratchet.signatureKeyPair = signatureKeyPair
        ratchet.senderKeyVersion = version

        GroupSessionRecord.removeOldChains(session)

        return {
            senderKey: {
                signatureKey: signatureKeyPair.pubKey,
                chainKey,
                previousCounter: ratchet.previousCounter,
                previousChainSignatureKey: previousRatchetKey,
            },
            session: GroupSessionRecord.serializeGroupSession(session),
        }
    }
    // createSenderKey1 => sendMessage 7 times  => resetSenderKey2 => sendMessage 4 times =>  resetSenderKey3 => sendMessage 5 times
    // createSenderKey1 => sendMessage 7 times  => resetSenderKey3 => sendMessage 5 times =>  resetSenderKey2 => sendMessage 4 times
    private createOrUpdateReceiverSessionJob = async (senderKey: SenderKey): Promise<void> => {
        let existingSession = await this.getSession(this.address.toString())

        if (existingSession) {
            if (existingSession?.chains[base64.fromByteArray(new Uint8Array(senderKey.signatureKey))]) {
                // the chain is already exists
                return Promise.resolve()
            }

            // todo remove this code
            if (senderKey.previousChainSignatureKey) {
                const previousRatchet =
                    existingSession.chains[base64.fromByteArray(new Uint8Array(senderKey.previousChainSignatureKey))]
                if (previousRatchet !== undefined) {
                    await this.fillMessageKeys(previousRatchet, senderKey.previousCounter).then(function () {
                        // in case there is some pending messages keep it for later
                        if (Object.keys(previousRatchet.messageKeys).length > 0) {
                            delete previousRatchet.chainKey.key
                            existingSession!.oldRatchetList[existingSession!.oldRatchetList.length] = {
                                added: Date.now(),
                                signaturePublicKey: senderKey.previousChainSignatureKey!,
                            }
                        } else {
                            // all the messages has been successfully decrypted, remove the chain.
                            delete existingSession!.chains[
                                base64.fromByteArray(new Uint8Array(senderKey.previousChainSignatureKey!))
                            ] // previousRatchet
                        }
                    })
                } else {
                    existingSession!.oldRatchetList[existingSession!.oldRatchetList.length] = {
                        added: Date.now(),
                        signaturePublicKey: senderKey.previousChainSignatureKey!,
                    }
                }
            }
            // add the new chain
            existingSession.chains[base64.fromByteArray(new Uint8Array(senderKey.signatureKey))] = {
                messageKeys: {},
                chainKey: { counter: -1, key: senderKey.chainKey },
                chainType: ChainType.RECEIVING,
            }
        } else {
            existingSession = {
                oldRatchetList: [],
                chains: {
                    [base64.fromByteArray(new Uint8Array(senderKey.signatureKey))]: {
                        chainKey: {
                            key: senderKey.chainKey,
                            counter: -1,
                        },
                        chainType: ChainType.RECEIVING,
                        messageKeys: {},
                    },
                },
            }
        }

        GroupSessionRecord.removeOldChains(existingSession)
        await this.storage.storeSession(
            this.address.toString(),
            GroupSessionRecord.serializeGroupSession(existingSession)
        )
    }

    private async getSession(encodedNumber: string): Promise<GroupSessionType | undefined> {
        const serialized = await this.storage.loadSession(encodedNumber)
        if (serialized === undefined) {
            return undefined
        }
        return GroupSessionRecord.deserializeGroupSession(serialized)
    }
}
