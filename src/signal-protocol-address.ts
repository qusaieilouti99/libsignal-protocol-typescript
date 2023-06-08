import { SignalProtocolAddressType, SignalProtocolGroupAddressType } from './'

export class SignalProtocolAddress implements SignalProtocolAddressType {
    static fromString(s: string): SignalProtocolAddress {
        if (!s.match(/.*\.\d+/)) {
            throw new Error(`Invalid SignalProtocolAddress string: ${s}`)
        }
        const parts = s.split('.')
        return new SignalProtocolAddress(parts[0], parseInt(parts[1]))
    }

    private _name: string
    private _deviceId: number
    constructor(_name: string, _deviceId: number) {
        this._name = _name
        this._deviceId = _deviceId
    }

    // Readonly properties
    get name(): string {
        return this._name
    }

    get deviceId(): number {
        return this._deviceId
    }

    // Expose properties as fuynctions for compatibility
    getName(): string {
        return this._name
    }

    getDeviceId(): number {
        return this._deviceId
    }

    toString(): string {
        return `${this._name}.${this._deviceId}`
    }

    equals(other: SignalProtocolAddressType): boolean {
        return other.name === this._name && other.deviceId == this._deviceId
    }
}

export class SignalProtocolGroupAddress implements SignalProtocolGroupAddressType {
    static fromString(s: string): SignalProtocolGroupAddress {
        if (!s.match(/.*\.\d+/)) {
            throw new Error(`Invalid SignalProtocolGroupAddress string: ${s}`)
        }
        const parts = s.split('.')
        return new SignalProtocolGroupAddress(parts[0], parts[1], parseInt(parts[2]))
    }

    private _groupId: string
    private _userId: string
    private _deviceId: number
    constructor(_groupId: string, _userId: string, _deviceId: number) {
        this._groupId = _groupId
        this._userId = _userId
        this._deviceId = _deviceId
    }

    // Readonly properties
    get groupId(): string {
        return this._groupId
    }

    get userId(): string {
        return this._userId
    }

    get deviceId(): number {
        return this._deviceId
    }

    // Expose properties as fuynctions for compatibility
    getGroupId(): string {
        return this._groupId
    }

    getUserId(): string {
        return this._userId
    }

    getDeviceId(): number {
        return this._deviceId
    }

    toString(): string {
        return `${this._groupId}.${this._userId}.${this._deviceId}`
    }

    equals(other: SignalProtocolGroupAddressType): boolean {
        return other.groupId === this._groupId && other.userId == this._userId && other.deviceId == this._deviceId
    }
}
