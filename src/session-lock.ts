/* eslint-disable @typescript-eslint/no-explicit-any */
/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session io ops on the database.
 */

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
import { queue, QueueObject } from 'async'

type JobType<T> = () => Promise<T>

export class SessionLock {
    private static queues: { [id: string]: QueueObject<any> } = {}

    static async queueJobForNumber<T>(id: string, runJob: JobType<T>): Promise<T> {
        if (!this.queues[id]) {
            this.queues[id] = queue<JobType<T>>(async (job, callback) => {
                try {
                    const result = await job() // Return the result from runJob
                    callback()
                    return result
                } finally {
                    console.log('finally')
                    if (this.queues[id].length() === 0) {
                        this.queues[id].kill()
                        delete this.queues[id]
                    }
                }
            })
        }

        const myQueue = this.queues[id]

        return await myQueue.push<T>(runJob) // Return the result from the wrapped function
    }

    // eslint-disable-next-line @typescript-eslint/no-empty-function
    static async clearQueue(): Promise<void> {}
}
