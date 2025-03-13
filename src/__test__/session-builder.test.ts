import { SessionBuilder } from '../session-builder'
import { SessionCipher } from '../session-cipher'
import { SessionRecord } from '../session-record'
import { SignalProtocolAddress } from '../signal-protocol-address'
import { FakeLogger } from './fake-logger'
import { SignalProtocolStore } from './storage-type'
import { generateIdentity, generatePreKeyBundle, assertEqualArrayBuffers } from '../__test-utils__/utils'
import * as utils from '../helpers'
import { KeyHelper } from '../key-helper'

jest.setTimeout(30000)

const ALICE_ADDRESS = new SignalProtocolAddress('+14151111111', 1)
const BOB_ADDRESS = new SignalProtocolAddress('+14152222222', 1)

describe('basic prekey v3', function () {
    const aliceStore = new SignalProtocolStore()
    const bobStore = new SignalProtocolStore()
    const bobPreKeyId = 1337
    const bobSignedKeyId = 1
    const fakeLogger = new FakeLogger()

    beforeAll(async () => {
        await Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)])
        const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId)
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS, fakeLogger)
        return builder.processPreKey(preKeyBundle)
    })

    const originalMessage = utils.binaryStringToArrayBuffer("L'homme est condamné à être libre")
    const nextMessage = utils.binaryStringToArrayBuffer(
        "condamné parce qu'il ne s'est pas crée lui-même, et par ailleurs cependant libre parce qu'une fois jeté dans le monde, il est responsable de tout ce qu'il fait."
    )
    const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS, fakeLogger)
    const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS, fakeLogger)

    test('basic prekey v3: creates a session', async () => {
        const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
        expect(record).toBeDefined()
        const sessionRecord = SessionRecord.deserialize(record!)
        expect(sessionRecord.haveOpenSession()).toBeTruthy()
        expect(sessionRecord.getOpenSession()).toBeDefined()
    })

    test('basic prekey v3: the session can encrypt', async () => {
        const ciphertext = await aliceSessionCipher.encrypt(originalMessage)
        expect(ciphertext.type).toBe(3) // PREKEY_BUNDLE
        const plaintext = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body!, 'binary')
        assertEqualArrayBuffers(plaintext, originalMessage) // assertEqualArrayBuffers(plaintext, originalMessage)
    })

    test('basic v3 NO PREKEY: the session can decrypt multiple v3 messages', async () => {
        const ciphertext0 = await aliceSessionCipher.encrypt(originalMessage)
        expect(ciphertext0.type).toBe(3) // PREKEY_BUNDLE
        const ciphertext1 = await aliceSessionCipher.encrypt(nextMessage)
        expect(ciphertext1.type).toBe(3) // PREKEY_BUNDLE
        const plaintext0 = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext0.body!, 'binary')
        assertEqualArrayBuffers(plaintext0, originalMessage)
        const plaintext1 = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext1.body!, 'binary')
        assertEqualArrayBuffers(plaintext1, nextMessage)
    })

    test('basic prekey v3: the session can decrypt', async () => {
        const ciphertext = await bobSessionCipher.encrypt(originalMessage)
        const plaintext = await aliceSessionCipher.decryptWhisperMessage(ciphertext.body!, 'binary')
        assertEqualArrayBuffers(plaintext, originalMessage)
    })

    test('basic prekey v3: accepts a new preKey with the same identity', async () => {
        const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1)
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS, fakeLogger)
        await builder.processPreKey(preKeyBundle)
        const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
        expect(record).toBeDefined()
        const sessionRecord = SessionRecord.deserialize(record!)
        expect(sessionRecord.haveOpenSession()).toBeTruthy()
        expect(sessionRecord.getOpenSession()).toBeDefined()
    })

    test('basic prekey v3: rejects untrusted identity keys', async () => {
        const newIdentity = await KeyHelper.generateIdentityKeyPair()
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS, fakeLogger)
        await expect(async () => {
            await builder.processPreKey({
                identityKey: newIdentity.pubKey,
                registrationId: 12356,
                signedPreKey: {
                    keyId: 2,
                    publicKey: new Uint8Array(33).buffer,
                    signature: new Uint8Array(32).buffer,
                },
            })
        }).rejects.toThrow('Identity key changed')
    })
})

describe('basic v3 NO PREKEY', function () {
    const aliceStore = new SignalProtocolStore()
    const fakeLogger = new FakeLogger()
    const bobStore = new SignalProtocolStore()
    const bobPreKeyId = 1337
    const bobSignedKeyId = 1

    beforeAll(async () => {
        await Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)])
        const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId)
        delete preKeyBundle.preKey
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS, fakeLogger)
        return builder.processPreKey(preKeyBundle)
    })

    const originalMessage = <ArrayBuffer>utils.binaryStringToArrayBuffer("L'homme est condamné à être libre")
    const nextMessage = <ArrayBuffer>(
        utils.binaryStringToArrayBuffer(
            "condamné parce qu'il ne s'est pas crée lui-même, et par ailleurs cependant libre parce qu'une fois jeté dans le monde, il est responsable de tout ce qu'il fait."
        )
    )
    const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS, fakeLogger)
    const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS, fakeLogger)

    test('basic v3 NO PREKEY: creates a session', async () => {
        const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
        expect(record).toBeDefined()
        const sessionRecord = SessionRecord.deserialize(record!)
        expect(sessionRecord.haveOpenSession()).toBeTruthy()
        expect(sessionRecord.getOpenSession()).toBeDefined()
    })

    test('basic v3 NO PREKEY: the session can encrypt', async () => {
        const ciphertext = await aliceSessionCipher.encrypt(originalMessage)
        expect(ciphertext.type).toBe(3) // PREKEY_BUNDLE

        const plaintext = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body!, 'binary')

        assertEqualArrayBuffers(plaintext, originalMessage)
    })

    test('basic v3 NO PREKEY: the session can decrypt multiple v3 messages', async () => {
        const ciphertext0 = await aliceSessionCipher.encrypt(originalMessage)
        expect(ciphertext0.type).toBe(3) // PREKEY_BUNDLE
        const ciphertext1 = await aliceSessionCipher.encrypt(nextMessage)
        expect(ciphertext1.type).toBe(3) // PREKEY_BUNDLE
        const plaintext0 = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext0.body!, 'binary')
        assertEqualArrayBuffers(plaintext0, originalMessage)
        const plaintext1 = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext1.body!, 'binary')
        assertEqualArrayBuffers(plaintext1, nextMessage)
    })

    test('basic v3 NO PREKEY: the session can decrypt', async () => {
        const ciphertext = await bobSessionCipher.encrypt(originalMessage)
        const plaintext = await aliceSessionCipher.decryptWhisperMessage(ciphertext.body!, 'binary')
        assertEqualArrayBuffers(plaintext, originalMessage)
    })

    test('basic v3 NO PREKEY: accepts a new preKey with the same identity', async () => {
        const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1)
        delete preKeyBundle.preKey
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS, fakeLogger)
        await builder.processPreKey(preKeyBundle)
        const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
        expect(record).toBeDefined()
        const sessionRecord = SessionRecord.deserialize(record!)
        expect(sessionRecord.haveOpenSession()).toBeTruthy()
        expect(sessionRecord.getOpenSession()).toBeDefined
    })

    test('basic v3 NO PREKEY: rejects untrusted identity keys', async () => {
        const newIdentity = await KeyHelper.generateIdentityKeyPair() //.then(function (newIdentity) {
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS, fakeLogger)
        await expect(async () => {
            await builder.processPreKey({
                identityKey: newIdentity.pubKey,
                registrationId: 12356,
                signedPreKey: {
                    keyId: 2,
                    publicKey: new Uint8Array(33).buffer,
                    signature: new Uint8Array(32).buffer,
                },
            })
        }).rejects.toThrow('Identity key changed')
    })
})
