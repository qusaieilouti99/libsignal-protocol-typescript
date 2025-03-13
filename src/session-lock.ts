/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session io ops on the database.
 */

const jobQueue: { [k: string]: Promise<unknown> } = {}

export type JobType<T> = () => Promise<T>

export class SessionLock {
    static queueJob<T>(id: string, runJob: JobType<T>): Promise<T> {
        const runPrevious = jobQueue[id] || Promise.resolve()
        const runCurrent = (jobQueue[id] = runPrevious.then(runJob, runJob))
        runCurrent
            .then(function () {
                if (jobQueue[id] === runCurrent) {
                    delete jobQueue[id]
                }
            })
            .catch(() => {
                // SessionLock callers should already have seen these errors on their own
                // Promise chains, but we need to handle them here too so we just save them
                // so callers can review them.
            })
        return runCurrent
    }
}
