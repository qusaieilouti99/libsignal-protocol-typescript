import { SessionLock } from '../session-lock'

async function sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms))
}
describe('session-lock', function () {
    test('return something', async () => {
        let value = ''
        await Promise.all([
            SessionLock.queueJob('channel1', async () => {
                await sleep(10)
                value += 'xyz'
                return Promise.resolve()
            }),
        ])

        expect(value).toBe('xyz')
    })

    test('return longshort', async () => {
        let value = ''
        await Promise.all([
            SessionLock.queueJob('channel1', async () => {
                await sleep(3000)
                value += 'long'
            }),
            SessionLock.queueJob('channel1', async () => {
                await sleep(1)
                value += 'short'
            }),
        ])

        expect(value).toBe('longshort')
    })

    test('return shortlong', async () => {
        let value = ''
        await Promise.all([
            SessionLock.queueJob('channel1', async () => {
                await sleep(1)
                value += 'short'
            }),
            SessionLock.queueJob('channel1', async () => {
                await sleep(2000)
                value += 'long'
            }),
        ])

        expect(value).toBe('shortlong')
    })

    test('multichannel', async () => {
        let value = ''
        await Promise.all([
            SessionLock.queueJob('channel1', async () => {
                await sleep(4000)
                value += 'long'
            }),
            SessionLock.queueJob('channel2', async () => {
                await sleep(1)
                value += 'ch2'
            }),
            SessionLock.queueJob('channel1', async () => {
                await sleep(1)
                value += 'short'
            }),
        ])
        const re = /ch2/gi
        const newstr = value.replace(re, '')
        expect(newstr).toBe('longshort')
    })
})
