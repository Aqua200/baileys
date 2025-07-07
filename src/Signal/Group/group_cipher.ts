import { decrypt, encrypt } from 'libsignal/src/crypto'
import queueJob from './queue-job'
import { SenderKeyMessage } from './sender-key-message'
import { SenderKeyName } from './sender-key-name'
import { SenderKeyRecord } from './sender-key-record'
import { SenderKeyState } from './sender-key-state'
import MAIN_LOGGER from '../../Utils/logger' // Importar el logger

const logger = MAIN_LOGGER.child({}) // Inicializar el logger

export interface SenderKeyStore {
	loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord>
	storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void>
}

export class GroupCipher {
	private readonly senderKeyStore: SenderKeyStore
	private readonly senderKeyName: SenderKeyName

	constructor(senderKeyStore: SenderKeyStore, senderKeyName: SenderKeyName) {
		this.senderKeyStore = senderKeyStore
		this.senderKeyName = senderKeyName
		logger.info(`GroupCipher initialized for sender: ${senderKeyName.toString()}.`) //
	}

	private queueJob<T>(awaitable: () => Promise<T>): Promise<T> {
		return queueJob(this.senderKeyName.toString(), awaitable)
	}

	public async encrypt(paddedPlaintext: Uint8Array | string): Promise<Uint8Array> {
		logger.debug(`Starting encryption for sender: ${this.senderKeyName.toString()}.`) //
		return await this.queueJob(async() => {
			const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName)
			if(!record) {
				logger.error(`No SenderKeyRecord found for encryption for ${this.senderKeyName.toString()}.`) //
				throw new Error('No SenderKeyRecord found for encryption')
			}

			const senderKeyState = record.getSenderKeyState()
			if(!senderKeyState) {
				logger.error(`No session to encrypt message for ${this.senderKeyName.toString()}.`) //
				throw new Error('No session to encrypt message')
			}

			const iteration = senderKeyState.getSenderChainKey().getIteration()
			const messageKey = senderKeyState.getSenderMessageKey()

			const ciphertext = await this.getCipherText(
				new Uint8Array(16), // IV (Initialization Vector) - typically random, here using a placeholder
				messageKey,
				paddedPlaintext
			)

			senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext())
			await this.senderKeyStore.storeSenderKey(this.senderKeyName, record)

			const senderKeyMessage = new SenderKeyMessage(
				senderKeyState.getKeyId(),
				iteration,
				ciphertext,
				senderKeyState.getSigningKey().privKey
			)
			logger.info(`Successfully encrypted message for sender: ${this.senderKeyName.toString()}, iteration: ${iteration}.`) //
			return senderKeyMessage.serialize()
		})
	}

	public async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
		logger.debug(`Starting decryption for sender: ${this.senderKeyName.toString()}.`) //
		return await this.queueJob(async() => {
			const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName)
			if(!record) {
				logger.error(`No SenderKeyRecord found for decryption for ${this.senderKeyName.toString()}.`) //
				throw new Error('No SenderKeyRecord found for decryption')
			}

			if(record.isEmpty()) {
				logger.error(`SenderKeyRecord is empty for decryption for ${this.senderKeyName.toString()}.`) //
				throw new Error('Empty SenderKeyRecord for decryption')
			}

			const senderKeyMessage = SenderKeyMessage.deserialize(ciphertext)
			logger.debug(`Deserialized SenderKeyMessage for ${this.senderKeyName.toString()} - Key ID: ${senderKeyMessage.getKeyId()}, Iteration: ${senderKeyMessage.getIteration()}, Message Version: ${senderKeyMessage.getMessageVersion()}.`) //

			const senderKeyState = record.getSenderKeyState(senderKeyMessage.getKeyId())

			senderKeyMessage.verifySignature(senderKeyState.getSigningKey().pubKey)

			const messageKey = this.getSenderMessageKey(
				senderKeyState,
				senderKeyMessage.getIteration()
			)

			const plaintext = await this.getPlainText(
				new Uint8Array(16), // IV - same placeholder as encryption, in a real scenario, it's part of the message or derived
				messageKey,
				senderKeyMessage.getCipherText()
			)
			await this.senderKeyStore.storeSenderKey(this.senderKeyName, record)
			logger.info(`Successfully decrypted message for sender: ${this.senderKeyName.toString()}, iteration: ${senderKeyMessage.getIteration()}.`) //
			return plaintext
		})
	}

	private getSenderMessageKey(senderKeyState: SenderKeyState, iteration: number): Uint8Array {
		const senderChainKey = senderKeyState.getSenderChainKey()
		if(iteration < senderChainKey.getIteration()) {
			if(senderKeyState.hasSenderMessageKey(iteration)) {
				const messageKey = senderKeyState.removeSenderMessageKey(iteration)
				if(!messageKey) {
					logger.error(`No sender message key found for iteration ${iteration} for ${this.senderKeyName.toString()}.`) //
					throw new Error('No sender message key found for iteration')
				}
				logger.debug(`Retrieved old sender message key for iteration: ${iteration} for ${this.senderKeyName.toString()}.`) //
				return messageKey
			}

			logger.warn(`Received message with old counter: ${senderChainKey.getIteration()}, requested: ${iteration} for ${this.senderKeyName.toString()}.`) //
			throw new Error(`Received message with old counter: ${senderChainKey.getIteration()}, ${iteration}`)
		}

		if(iteration - senderChainKey.getIteration() > 2000) {
			logger.error(`Over 2000 messages into the future for ${this.senderKeyName.toString()}! Current: ${senderChainKey.getIteration()}, requested: ${iteration}.`) //
			throw new Error('Over 2000 messages into the future!')
		}

		while (senderChainKey.getIteration() < iteration) {
			senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey())
			senderChainKey = senderChainKey.getNext()
		}

		senderKeyState.setSenderChainKey(senderChainKey.getNext())
		const messageKey = senderChainKey.getSenderMessageKey()
		logger.debug(`Generated new sender message key for iteration: ${iteration} for ${this.senderKeyName.toString()}.`) //
		return messageKey
	}

	private async getPlainText(iv: Uint8Array, key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
		logger.debug('Attempting to decrypt ciphertext.') //
		try {
			const plaintext = decrypt(key, ciphertext, iv)
			logger.debug('Ciphertext decrypted successfully.') //
			return plaintext
		} catch (e) {
			logger.error(`Error decrypting ciphertext: ${e}.`) //
			throw new Error('InvalidMessageException')
		}
	}

	private async getCipherText(
		iv: Uint8Array | string,
		key: Uint8Array | string,
		plaintext: Uint8Array | string
	): Promise<Buffer> {
		logger.debug('Attempting to encrypt plaintext.') //
		try {
			const ivBuffer = typeof iv === 'string' ? Buffer.from(iv, 'base64') : iv
			const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'base64') : key
			const plaintextBuffer = typeof plaintext === 'string' ? Buffer.from(plaintext, 'base64') : plaintext
			const ciphertext = encrypt(keyBuffer, plaintextBuffer, ivBuffer)
			logger.debug('Plaintext encrypted successfully.') //
			return ciphertext
		} catch (e) {
			logger.error(`Error encrypting plaintext: ${e}.`) //
			throw e
		}
	}
}
