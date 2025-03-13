import { LoggerType } from '../types'

export class FakeLogger implements LoggerType {
    sendEvent(eventName: string, data?: Record<string, unknown> | undefined) {
        return
    }
}
