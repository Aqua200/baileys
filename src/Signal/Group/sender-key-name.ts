import MAIN_LOGGER from '../../Utils/logger' // Importar el logger

const logger = MAIN_LOGGER.child({}) // Inicializar el logger

interface Sender {
	id: string
	deviceId: number
	toString(): string
}

function isNull(str: string | null): boolean {
	return str === null || str === ''
}

function intValue(num: number): number {
	const MAX_VALUE = 0x7fffffff
	const MIN_VALUE = -0x80000000
	if(num > MAX_VALUE || num < MIN_VALUE) {
		return num & 0xffffffff
	}

	return num
}

function hashCode(strKey: string): number {
	let hash = 0
	if(!isNull(strKey)) {
		for (let i = 0; i < strKey.length; i++) {
			hash = hash * 31 + strKey.charCodeAt(i)
			hash = intValue(hash)
		}
	}

	return hash
}

export class SenderKeyName {
	private readonly groupId: string
	private readonly sender: Sender

	constructor(groupId: string, sender: Sender) {
		this.groupId = groupId
		this.sender = sender
		logger.debug(`SenderKeyName created for Group ID: "${this.groupId}", Sender ID: "${this.sender.id}", Device ID: ${this.sender.deviceId}.`) //
	}

	public getGroupId(): string {
		return this.groupId
	}

	public getSender(): Sender {
		return this.sender
	}

	public serialize(): string {
		return `${this.groupId}::${this.sender.id}::${this.sender.deviceId}`
	}

	public toString(): string {
		return this.serialize()
	}

	public equals(other: SenderKeyName | null): boolean {
		if(other === null) {
			logger.debug(`Comparison with null SenderKeyName for ${this.toString()}. Returning false.`) //
			return false
		}
		const isEqual = this.groupId === other.groupId && this.sender.id === other.sender.id && this.sender.deviceId === other.sender.deviceId
		logger.debug(`Comparing SenderKeyName ${this.toString()} with ${other.toString()}. Result: ${isEqual}.`) //
		return isEqual
	}

	public hashCode(): number {
		const hashVal = hashCode(this.serialize())
		logger.debug(`Calculated hash code for ${this.toString()}: ${hashVal}.`) //
		return hashVal
	}
}
