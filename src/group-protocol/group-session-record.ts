import * as util from "../helpers";
import {abToS, chainArrayBufferToString, chainStringToArrayBuffer, keyPairArrayBufferToString, keyPairStirngToArrayBuffer, OLD_RATCHETS_MAX_LENGTH, toAB} from "../session-record";
import {Chain, GroupOldRatchetInfo, GroupRatchet, GroupSessionType, SessionType} from "../session-types";

export class GroupSessionRecord {
    static deserializeGroupSession(serialized: string): GroupSessionType {
        const json = JSON.parse(serialized)
        return this.groupSessionTypeStringToArrayBuffer(json as GroupSessionType<string>)
    }

    static serializeGroupSession(session:GroupSessionType): string {
        const json = this.groupSessionTypeArrayBufferToString(session)
        return JSON.stringify(json)
    }

    static groupSessionTypeArrayBufferToString(session: GroupSessionType<ArrayBuffer>): GroupSessionType<string> {
        const { currentRatchet, oldRatchetList, chains } = session
        const newChains: { [sigKeyString: string]: Chain<string> } = {}
        for (const k of Object.keys(chains)) {
            newChains[k] = chainArrayBufferToString(chains[k])
        }
        return {
            currentRatchet: this.groupRatchetArrayBufferToString(currentRatchet),
            oldRatchetList: oldRatchetList.map(this.groupOldRatchetInfoArrayBufferToString),
            chains: newChains,
        }
    }

    static groupRatchetArrayBufferToString(ratchet: GroupRatchet<ArrayBuffer>): GroupRatchet<string> {
        return {
            signatureKeyPair:ratchet.signatureKeyPair && keyPairArrayBufferToString(ratchet.signatureKeyPair),
            signaturePublicKey:abToS(ratchet.signaturePublicKey),
            previousCounter: ratchet.previousCounter,
            added: ratchet.added,
        }
    }

    static groupOldRatchetInfoArrayBufferToString(ori: GroupOldRatchetInfo<ArrayBuffer>): GroupOldRatchetInfo<string> {
        return {
            signaturePublicKey: abToS(ori.signaturePublicKey),
            added: ori.added,
        }
    }


    static groupSessionTypeStringToArrayBuffer(json: GroupSessionType<string>): GroupSessionType<ArrayBuffer> {
        const { currentRatchet, oldRatchetList, chains } = json
        const newChains: { [sigKeyString: string]: Chain<ArrayBuffer> } = {}
        for (const k of Object.keys(chains)) {
            newChains[k] = chainStringToArrayBuffer(chains[k])
        }
        return {
            currentRatchet: this.groupRatchetStringToArrayBuffer(currentRatchet),
            oldRatchetList: oldRatchetList.map(this.groupOldRatchetInfoStringToArrayBuffer),
            chains: newChains,
        }
    }

    static groupRatchetStringToArrayBuffer(ratchet: GroupRatchet<string>): GroupRatchet<ArrayBuffer> {
        return {
            signaturePublicKey:toAB(ratchet.signaturePublicKey),
            signatureKeyPair:ratchet.signatureKeyPair && keyPairStirngToArrayBuffer(ratchet.signatureKeyPair),
            previousCounter: ratchet.previousCounter,
            added: ratchet.added,
        }
    }

    static groupOldRatchetInfoStringToArrayBuffer(ori: GroupOldRatchetInfo<string>): GroupOldRatchetInfo<ArrayBuffer> {
        return {
            signaturePublicKey:toAB(ori.signaturePublicKey),
            added: ori.added,
        }
    }

    static removeOldChains(session: GroupSessionType): void {
        // Sending ratchets are always removed when we step because we never need them again
        // Receiving ratchets are added to the oldRatchetList, which we parse
        // here and remove all but the last ten.
        while (session.oldRatchetList.length > OLD_RATCHETS_MAX_LENGTH) {
            let index = 0
            let oldest = session.oldRatchetList[0]
            for (let i = 0; i < session.oldRatchetList.length; i++) {
                if (session.oldRatchetList[i].added < oldest.added) {
                    oldest = session.oldRatchetList[i]
                    index = i
                }
            }
            const idx = util.arrayBufferToString(oldest.signaturePublicKey)
            if (!idx) {
                throw new Error(`invalid index for chain`)
            }

            const oldestDate = new Date(oldest.added)
            // this means the oldest chain has expired, so we remove it
            // 30 days after the date it's added at => expired
            if(Date.now() > oldestDate.setDate(oldestDate.getDate() + 30)){
                delete session.chains[idx]
                session.oldRatchetList.splice(index, 1)
            }else{
                // prevent infinite loop
                break
            }
        }
    }
}