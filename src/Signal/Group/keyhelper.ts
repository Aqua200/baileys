import * as nodeCrypto from 'crypto'
import { generateKeyPair } from 'libsignal/src/curve'
import MAIN_LOGGER from '../../Utils/logger' // Importar el logger

const logger = MAIN_LOGGER.child({}) // Inicializar el logger

type KeyPairType = ReturnType<typeof generateKeyPair>

export function generateSenderKey(): Buffer {
	const senderKey = nodeCrypto.randomBytes(32)
	logger.debug('Generated new sender key.') //
	return senderKey
}

export function generateSenderKeyId(): number {
	const senderKeyId = nodeCrypto.randomInt(2147483647)
	logger.debug(`Generated new sender key ID: ${senderKeyId}.`) //
	return senderKeyId
}

export interface SigningKeyPair {
	public: Buffer
	private: Buffer
}

export function generateSenderSigningKey(key?: KeyPairType): SigningKeyPair {
	let actualKeyPair: KeyPairType
	if(!key) {
		actualKeyPair = generateKeyPair()
		logger.debug('Generated new sender signing key pair.') //
	} else {
		actualKeyPair = key
		logger.debug('Using provided key pair to generate sender signing key.') //
	}

	const signingKeyPair = {
		public: Buffer.from(actualKeyPair.pubKey),
		private: Buffer.from(actualKeyPair.privKey)
	}
	logger.debug('Formatted sender signing key pair.') //
	return signingKeyPair
}
