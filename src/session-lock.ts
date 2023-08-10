/* eslint-disable @typescript-eslint/no-explicit-any */
/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session io ops on the database.
 */
import PQueue from 'p-queue'
/*const jobQueue: { [k: string]: Promise<any> } = {}

export type JobType<T> = () => Promise<T>

export class SessionLock {
    static errors: any[] = []
    static _promises: Promise<any>[] = []
    static queueJobForNumber<T>(id: string, runJob: JobType<T>): Promise<T> {
        const runPrevious = jobQueue[id] || Promise.resolve()
        const runCurrent = (jobQueue[id] = runPrevious.then(runJob, runJob))
        const promise = runCurrent
            .then(function () {
                if (jobQueue[id] === runCurrent) {
                    delete jobQueue[id]
                }
            })
            .catch((e) => {
                // SessionLock callers should already have seen these errors on their own
                // Promise chains, but we need to handle them here too so we just save them
                // so callers can review them.
                SessionLock.errors.push(e)
            })
        SessionLock._promises.push(promise)
        return runCurrent
    }

    static async clearQueue(): Promise<void> {
        await Promise.all(SessionLock._promises)
    }
}*/

type JobType<T> = () => Promise<T>

export class SessionLock {
    private static queues: { [id: string]: PQueue } = {}

    static async queueJobForNumber<T>(id: string, runJob: JobType<T>): Promise<T> {
        if (!this.queues[id]) {
            this.queues[id] = new PQueue({ concurrency: 1 })
        }

        const queue = this.queues[id]

        const result = await queue.add(async () => {
            try {
                return await runJob() // Return the result from runJob
            } finally {
                console.log('finally')
                if (queue.size === 0) {
                    delete this.queues[id]
                }
            }
        })

        return result as T // Return the result from the wrapped function
    }

    static async clearQueue(id: string): Promise<void> {
        if (this.queues[id]) {
            await this.queues[id].onIdle()
            delete this.queues[id]
        }
    }
}
