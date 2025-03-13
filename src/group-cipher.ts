import * as util from './helpers'
import { SessionLock } from './session-lock'
import { Chain, ChainType, GroupSessionType, LocalSenderKey, SenderKey } from './session-types'
import { LoggerType, SignalProtocolGroupAddressType, StorageType } from './types'
import * as Internal from './internal'
import * as base64 from 'base64-js'
import { GroupWhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts'
import { GroupSessionRecord } from './group-session-record'

export class GroupCipher {
    address: SignalProtocolGroupAddressType
    storage: StorageType
    logger: LoggerType

    constructor(storage: StorageType, address: SignalProtocolGroupAddressType, logger: LoggerType) {
        this.address = address
        this.storage = storage
        this.logger = logger
    }

    encrypt(buffer: ArrayBuffer): Promise<{ cipherText: string; senderKeyVersion: number }> {
        return SessionLock.queueJob(this.address.toString(), () => this.encryptJob(buffer))
    }

    createSenderSession(version: number): Promise<SenderKey<string>> {
        return SessionLock.queueJob(this.address.toString(), () => this.createSenderSessionJob(version))
    }

    createOrUpdateReceiverSession(senderKey: SenderKey): Promise<void> {
        return SessionLock.queueJob(this.address.toString(), () => this.createOrUpdateReceiverSessionJob(senderKey))
    }

    resetSenderSession(version: number): Promise<SenderKey<string>> {
        return SessionLock.queueJob(this.address.toString(), () => this.resetSenderSessionJob(version))
    }

    decrypt(buff: string | ArrayBuffer, encoding?: string, textId = ''): Promise<ArrayBuffer> {
        return SessionLock.queueJob(this.address.toString(), () => this.decryptJob(buff, encoding, textId))
    }

    private encryptJob = async (buffer: ArrayBuffer) => {
        if (!(buffer instanceof ArrayBuffer)) {
            throw new Error('Expected buffer to be an ArrayBuffer')
        }

        const address = this.address.toString()
        const msg = GroupWhisperMessage.fromJSON({})
        const session = await this.getSession(address)
        if (!session) {
            this.logger.sendEvent(`group-encrypt:address=${this.address.toString()}`, {
                functionName: 'encryptJob',
                error: 'no-session-to-encrypt',
            })
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

        this.logger.sendEvent(`group-encrypt:address=${this.address.toString()}`, {
            functionName: 'encryptJob',
            info: 'group text encrypted successfully.',
            senderKeyVersion: session.currentRatchet!.senderKeyVersion,
            msgCounter: msg.counter,
            previousCounter: msg.previousCounter,
            signature: msg.signature,
        })

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

    private async decryptJob(buff: string | ArrayBuffer, encoding?: string, textId = ''): Promise<ArrayBuffer> {
        encoding = encoding || 'binary'
        if (encoding !== 'binary') {
            this.logger.sendEvent(`group-decrypt:address=${this.address.toString()}`, {
                functionName: 'decryptJob',
                error: `unsupported encoding: ${encoding}`,
            })
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
            this.logger.sendEvent(`group-decrypt:address=${this.address.toString()}`, {
                functionName: 'decryptJob',
                error: `no session`,
            })
            const e = new Error('No record for device ' + address)
            e.name = 'NO_SESSION'
            throw e
        }

        const chain = session.chains[base64.fromByteArray(message.signaturePublicKey)]
        if (!chain) {
            this.logger.sendEvent(`group-decrypt:address=${this.address.toString()}`, {
                functionName: 'decryptJob',
                error: `no chain for ${base64.fromByteArray(message.signaturePublicKey)}`,
            })
            const e = new Error('no chain found for key ')
            e.name = 'NO_CHAIN'
            throw e
        }

        if (chain?.chainType === ChainType.SENDING) {
            this.logger.sendEvent(`group-decrypt:address=${this.address.toString()}`, {
                functionName: 'decryptJob',
                error: `Tried to decrypt on a sending chain`,
            })
            throw new Error('Tried to decrypt on a sending chain')
        }

        await this.fillMessageKeys(chain, message.counter)

        const messageKey = chain.messageKeys[message.counter]
        if (messageKey === undefined) {
            const alreadyDecryptedText = await this.storage.getDecryptedText(textId)
            if (alreadyDecryptedText) {
                this.logger.sendEvent(`group-decrypt:address=${this.address.toString()}`, {
                    functionName: 'decryptJob',
                    info: `found already decrypted text saved locally for ${textId}`,
                })
                return alreadyDecryptedText
            }

            this.logger.sendEvent(`group-decrypt:address=${this.address.toString()}`, {
                functionName: 'decryptJob',
                error: `Message key not found. The counter was repeated or the key was not filled. for message counter ${message.counter}`,
            })
            throw new Error('Message key not found. The counter was repeated or the key was not filled.')
        }

        const keys = await Internal.HKDF(messageKey, new ArrayBuffer(32), 'WhisperMessageKeys')

        const plaintext = await Internal.crypto.decrypt(
            keys[0],
            util.uint8ArrayToArrayBuffer(message.ciphertext),
            keys[2].slice(0, 16)
        )
        await this.storage.storeDecryptedText(textId, plaintext)

        this.logger.sendEvent(`group-decrypt:address=${this.address.toString()}`, {
            functionName: 'decryptJob',
            info: `successfully decrypted and saved locally for ${textId} and the key deleted`,
            msgCounter: message.counter,
        })
        delete chain.messageKeys[message.counter]
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
            this.logger.sendEvent(`group-encrypt:address=${this.address.toString()}`, {
                functionName: 'prepareChain',
                error: 'ratchet missing signaturePublicKey',
            })
            throw new Error(`ratchet missing signaturePublicKey`)
        }

        msg.signaturePublicKey = new Uint8Array(session.currentRatchet.signaturePublicKey)

        const chain = session.chains[base64.fromByteArray(msg.signaturePublicKey)]

        if (chain?.chainType === ChainType.RECEIVING) {
            this.logger.sendEvent(`group-encrypt:address=${this.address.toString()}`, {
                functionName: 'prepareChain',
                error: 'Tried to encrypt on a receiving chain',
            })
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
            this.logger.sendEvent(`group-encrypt&decrypt:address=${this.address.toString()}`, {
                functionName: 'fillMessageKeys',
                error: 'Got invalid request to extend chain after it was already closed',
            })
            throw new Error('Got invalid request to extend chain after it was already closed')
        }

        const ckey = chain.chainKey.key
        if (!ckey) {
            this.logger.sendEvent(`group-encrypt&decrypt:address=${this.address.toString()}`, {
                functionName: 'fillMessageKeys',
                error: 'hain key is missing',
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

        this.logger.sendEvent(`group-encrypt&decrypt:address=${this.address.toString()}`, {
            functionName: 'fillMessageKeys',
            info: 'derived a new key successfully ',
            chainKeyCounter: chain.chainKey.counter,
        })

        await this.fillMessageKeys(chain, counter)
    }

    private async generateGroupSenderKey(): Promise<LocalSenderKey> {
        // this will be used for signing the cipher messages
        const signatureKeyPair = await Internal.crypto.createKeyPair()
        // this will be used for deriving the messages keys
        const chainKey = await Internal.crypto.generateAesKey()

        return { signatureKeyPair, chainKey }
    }

    private createSenderSessionJob = async (version: number): Promise<SenderKey<string>> => {
        let session = await this.getSession(this.address.toString())

        if (session) {
            this.logger.sendEvent(`group-create-session:address=${this.address.toString()}`, {
                functionName: 'createSenderSessionJob',
                error: `SENDER_KEY_ALREADY_CREATED`,
            })
            throw new Error(`SENDER_KEY_ALREADY_CREATED`)
        }

        // generate keys
        const { signatureKeyPair, chainKey } = await this.generateGroupSenderKey()
        // create the session

        session = {
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
        // TODO check race cond
        await this.storage.storeSession(this.address.toString(), GroupSessionRecord.serializeGroupSession(session))
        const senderKey = GroupSessionRecord.serializeSenderKey({
            signatureKey: signatureKeyPair.pubKey,
            chainKey,
            previousCounter: 0,
            senderKeyVersion: version,
        })

        this.logger.sendEvent(`group-create-session:address=${this.address.toString()}`, {
            functionName: 'createSenderSessionJob',
            info: `successfully stored the session for sender key`,
            senderKeyVersion: version,
            signaturePubKey: senderKey.signatureKey,
        })
        await this.storage.addPendingSenderKeyAtomically(this.address.toString(), version, senderKey)
        this.logger.sendEvent(`group-create-session:address=${this.address.toString()}`, {
            functionName: 'createSenderSessionJob',
            info: `successfully added pending sender key`,
            senderKeyVersion: version,
            signaturePubKey: senderKey.signatureKey,
        })
        return senderKey
    }

    private resetSenderSessionJob = async (version: number): Promise<SenderKey<string>> => {
        // generate keys
        const { signatureKeyPair, chainKey } = await this.generateGroupSenderKey()
        // update the session
        const session = await this.getSession(this.address.toString())

        if (!session) {
            this.logger.sendEvent(`group-reset-session:address=${this.address.toString()}`, {
                functionName: 'resetSenderSessionJob',
                error: `No session for address`,
            })
            throw new Error(`No session for address ${this.address.toString()}`)
        }

        if (session.currentRatchet!.senderKeyVersion >= version) {
            this.logger.sendEvent(`group-reset-session:address=${this.address.toString()}`, {
                functionName: 'resetSenderSessionJob',
                error: `SENDER_KEY_ALREADY_CREATED`,
            })
            throw new Error(`SENDER_KEY_ALREADY_CREATED`)
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
        // TODO check race cond
        await this.storage.storeSession(this.address.toString(), GroupSessionRecord.serializeGroupSession(session))
        const senderKey = GroupSessionRecord.serializeSenderKey({
            signatureKey: signatureKeyPair.pubKey,
            chainKey,
            previousCounter: ratchet.previousCounter,
            previousChainSignatureKey: previousRatchetKey,
            senderKeyVersion: version,
        })

        this.logger.sendEvent(`group-reset-session:address=${this.address.toString()}`, {
            functionName: 'resetSenderSessionJob',
            info: `successfully stored the session for sender key`,
            senderKeyVersion: version,
            signaturePubKey: senderKey.signatureKey,
        })
        await this.storage.addPendingSenderKeyAtomically(this.address.toString(), version, senderKey)
        this.logger.sendEvent(`group-reset-session:address=${this.address.toString()}`, {
            functionName: 'resetSenderSessionJob',
            info: `successfully added pending sender key`,
            senderKeyVersion: version,
            signaturePubKey: senderKey.signatureKey,
        })
        return senderKey
    }
    // createSenderKey1 => sendMessage 7 times  => resetSenderKey2 => sendMessage 4 times =>  resetSenderKey3 => sendMessage 5 times
    // createSenderKey1 => sendMessage 7 times  => resetSenderKey3 => sendMessage 5 times =>  resetSenderKey2 => sendMessage 4 times
    private createOrUpdateReceiverSessionJob = async (senderKey: SenderKey): Promise<void> => {
        let existingSession = await this.getSession(this.address.toString())

        if (existingSession) {
            if (existingSession?.chains[base64.fromByteArray(new Uint8Array(senderKey.signatureKey))]) {
                // the chain is already exists
                this.logger.sendEvent(`group-receiver-session:address=${this.address.toString()}`, {
                    functionName: 'createOrUpdateReceiverSessionJob',
                    info: `there is already existing session for this address`,
                    senderKeyVersion: senderKey.senderKeyVersion,
                    signaturePubKey: base64.fromByteArray(new Uint8Array(senderKey.signatureKey)),
                })
                return Promise.resolve()
            }

            // todo remove this code
            if (senderKey.previousChainSignatureKey) {
                const previousChain =
                    existingSession.chains[base64.fromByteArray(new Uint8Array(senderKey.previousChainSignatureKey))]
                if (previousChain !== undefined) {
                    await this.fillMessageKeys(previousChain, senderKey.previousCounter).then(function () {
                        // in case there is some pending messages keep it for later
                        if (Object.keys(previousChain.messageKeys).length > 0) {
                            delete previousChain.chainKey.key
                            existingSession!.oldRatchetList[existingSession!.oldRatchetList.length] = {
                                added: Date.now(),
                                signaturePublicKey: senderKey.previousChainSignatureKey!,
                            }
                        } else {
                            // all the messages has been successfully decrypted, remove the chain.
                            delete existingSession!.chains[
                                base64.fromByteArray(new Uint8Array(senderKey.previousChainSignatureKey!))
                            ] // previousChain
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

        this.logger.sendEvent(`group-receiver-session:address=${this.address.toString()}`, {
            functionName: 'createOrUpdateReceiverSessionJob',
            info: `successfully stored the receiver session for sender key`,
            senderKeyVersion: senderKey.senderKeyVersion,
            signaturePubKey: base64.fromByteArray(new Uint8Array(senderKey.signatureKey)),
        })
    }

    private async getSession(encodedNumber: string): Promise<GroupSessionType | undefined> {
        const serialized = await this.storage.loadSession(encodedNumber)
        if (serialized === undefined) {
            return undefined
        }
        return GroupSessionRecord.deserializeGroupSession(serialized)
    }
}
