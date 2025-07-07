import { calculateMAC } from 'libsignal/src/crypto'
import { SenderMessageKey } from './sender-message-key'
import MAIN_LOGGER from '../../Utils/logger' // Importar el logger

const logger = MAIN_LOGGER.child({}) // Inicializar el logger

export class SenderChainKey {
	private readonly MESSAGE_KEY_SEED: Uint8Array = Buffer.from([0x01])
	private readonly CHAIN_KEY_SEED: Uint8Array = Buffer.from([0x02])
	private readonly iteration: number
	private readonly chainKey: Buffer

	constructor(iteration: number, chainKey: any) {
		this.iteration = iteration
		if(chainKey instanceof Buffer) {
			this.chainKey = chainKey
		} else {
			this.chainKey = Buffer.from(chainKey || [])
		}
		logger.debug(`SenderChainKey initialized with iteration: ${this.iteration}.`) //
	}

	public getIteration(): number {
		return this.iteration
	}

	public getSenderMessageKey(): SenderMessageKey {
		const messageKey = new SenderMessageKey(this.iteration, this.getDerivative(this.MESSAGE_KEY_SEED, this.chainKey))
		logger.debug(`Derived SenderMessageKey for iteration: ${this.iteration}.`) //
		return messageKey
	}

	public getNext(): SenderChainKey {
		const nextChainKey = new SenderChainKey(this.iteration + 1, this.getDerivative(this.CHAIN_KEY_SEED, this.chainKey))
		logger.debug(`Derived next SenderChainKey for iteration: ${this.iteration + 1}.`) //
		return nextChainKey
	}

	public getSeed(): Uint8Array {
		return this.chainKey
	}

	private getDerivative(seed: Uint8Array, key: Buffer): Uint8Array {
		logger.debug('Calculating MAC for key derivation.') //
		return calculateMAC(key, seed)
	}
}
