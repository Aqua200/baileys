import { calculateSignature, verifySignature } from 'libsignal/src/curve'
import { proto } from '../../../WAProto'
import { CiphertextMessage } from './ciphertext-message'
import MAIN_LOGGER from '../../Utils/logger' // Importar el logger

const logger = MAIN_LOGGER.child({}) // Inicializar el logger

interface SenderKeyMessageStructure {
	id: number
	iteration: number
	ciphertext: string | Buffer
}

export class SenderKeyMessage extends CiphertextMessage {
	private readonly SIGNATURE_LENGTH = 64
	private readonly messageVersion: number
	private readonly keyId: number
	private readonly iteration: number
	private readonly ciphertext: Uint8Array
	private readonly signature: Uint8Array
	private readonly serialized: Uint8Array

	constructor(
		keyId?: number | null,
		iteration?: number | null,
		ciphertext?: Uint8Array | null,
		signatureKey?: Uint8Array | null,
		serialized?: Uint8Array | null
	) {
		super()
		logger.debug('SenderKeyMessage constructor called.') //

		if(serialized) {
			try {
				const version = serialized[0]
				const message = serialized.slice(1, serialized.length - this.SIGNATURE_LENGTH)
				const signature = serialized.slice(-1 * this.SIGNATURE_LENGTH)
				const senderKeyMessage = proto.SenderKeyMessage.decode(message).toJSON() as SenderKeyMessageStructure

				this.serialized = serialized
				this.messageVersion = (version & 0xff) >> 4
				this.keyId = senderKeyMessage.id
				this.iteration = senderKeyMessage.iteration
				this.ciphertext =
					typeof senderKeyMessage.ciphertext === 'string'
						? Buffer.from(senderKeyMessage.ciphertext, 'base64')
						: senderKeyMessage.ciphertext
				this.signature = signature
				logger.debug(`SenderKeyMessage deserialized. Key ID: ${this.keyId}, Iteration: ${this.iteration}.`) //
			} catch (e) {
				logger.error(`Error deserializing SenderKeyMessage: ${e}.`, e) // Registrar el error
				throw new Error(`Invalid SenderKeyMessage: ${e}`) // Relanzar un error más específico
			}
		} else {
			const version = (((this.CURRENT_VERSION << 4) | this.CURRENT_VERSION) & 0xff) % 256
			const ciphertextBuffer = Buffer.from(ciphertext!)
			const message = proto.SenderKeyMessage.encode(
				proto.SenderKeyMessage.create({
					id: keyId!,
					iteration: iteration!,
					ciphertext: ciphertextBuffer
				})
			).finish()

			logger.debug('Calculating signature for new SenderKeyMessage.') //
			const signature = this.getSignature(signatureKey!, Buffer.concat([Buffer.from([version]), message]))

			this.serialized = Buffer.concat([Buffer.from([version]), message, Buffer.from(signature)])
			this.messageVersion = this.CURRENT_VERSION
			this.keyId = keyId!
			this.iteration = iteration!
			this.ciphertext = ciphertextBuffer
			this.signature = signature
			logger.debug(`New SenderKeyMessage created. Key ID: ${this.keyId}, Iteration: ${this.iteration}.`) //
		}
	}

	public serialize(): Uint8Array {
		return this.serialized
	}

	public getType(): number {
		return this.SENDERKEY_TYPE
	}

	public getKeyId(): number {
		return this.keyId
	}

	public getIteration(): number {
		return this.iteration
	}

	public getCipherText(): Uint8Array {
		return this.ciphertext
	}

	public verifySignature(signatureKey: Uint8Array): void {
		logger.debug(`Verifying signature for SenderKeyMessage with Key ID: ${this.keyId}.`) //
		const part1 = this.serialized.slice(0, this.serialized.length - this.SIGNATURE_LENGTH)
		const part2 = this.serialized.slice(-1 * this.SIGNATURE_LENGTH)
		const res = verifySignature(signatureKey, part1, part2)
		if(!res) {
			logger.error(`Signature verification failed for SenderKeyMessage with Key ID: ${this.keyId}.`) //
			throw new Error('Invalid signature!')
		}
		logger.debug(`Signature verified successfully for SenderKeyMessage with Key ID: ${this.keyId}.`) //
	}

	private getSignature(signatureKey: Uint8Array, serialized: Uint8Array): Uint8Array {
		return Buffer.from(calculateSignature(signatureKey, serialized))
	}
}
