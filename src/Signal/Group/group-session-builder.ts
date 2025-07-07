import * as keyhelper from './keyhelper'
import { SenderKeyDistributionMessage } from './sender-key-distribution-message'
import { SenderKeyName } from './sender-key-name'
import { SenderKeyRecord } from './sender-key-record'
import MAIN_LOGGER from '../../Utils/logger' // Importar el logger

const logger = MAIN_LOGGER.child({}) // Inicializar el logger

interface SenderKeyStore {
	loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord>
	storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void>
}

export class GroupSessionBuilder {
	private readonly senderKeyStore: SenderKeyStore

	constructor(senderKeyStore: SenderKeyStore) {
		this.senderKeyStore = senderKeyStore
		logger.info('GroupSessionBuilder initialized.') //
	}

	public async process(
		senderKeyName: SenderKeyName,
		senderKeyDistributionMessage: SenderKeyDistributionMessage
	): Promise<void> {
		logger.debug(`Processing sender key distribution message for ${senderKeyName.toString()}.`) //
		try {
			const senderKeyRecord = await this.senderKeyStore.loadSenderKey(senderKeyName)
			senderKeyRecord.addSenderKeyState(
				senderKeyDistributionMessage.getId(),
				senderKeyDistributionMessage.getIteration(),
				senderKeyDistributionMessage.getChainKey(),
				senderKeyDistributionMessage.getSignatureKey()
			)
			await this.senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord)
			logger.info(`Successfully processed sender key distribution message for ${senderKeyName.toString()}.`) //
		} catch (error) {
			logger.error(`Error processing sender key distribution message for ${senderKeyName.toString()}: ${error}`) //
			throw error
		}
	}

	public async create(senderKeyName: SenderKeyName): Promise<SenderKeyDistributionMessage> {
		logger.debug(`Creating new sender key distribution message for ${senderKeyName.toString()}.`) //
		const senderKeyRecord = await this.senderKeyStore.loadSenderKey(senderKeyName)

		if(senderKeyRecord.isEmpty()) {
			logger.debug(`Sender key record is empty for ${senderKeyName.toString()}. Generating new keys.`) //
			const keyId = keyhelper.generateSenderKeyId()
			const senderKey = keyhelper.generateSenderKey()
			const signingKey = keyhelper.generateSenderSigningKey()

			senderKeyRecord.setSenderKeyState(keyId, 0, senderKey, signingKey)
			await this.senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord)
		}

		const state = senderKeyRecord.getSenderKeyState()
		if(!state) {
			logger.error(`No session state available after creating/loading sender key record for ${senderKeyName.toString()}.`) //
			throw new Error('No session state available')
		}

		logger.info(`Successfully created sender key distribution message for ${senderKeyName.toString()}.`) //
		return new SenderKeyDistributionMessage(
			state.getKeyId(),
			state.getSenderChainKey().getIteration(),
			state.getSenderChainKey().getSeed(),
			state.getSigningKey().pubKey,
			undefined
		)
	}
}
