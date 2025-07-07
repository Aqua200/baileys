import * as libsignal from 'libsignal'
import { SignalAuthState } from '../Types'
import { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode } from '../WABinary'
import type { SenderKeyStore } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'
import MAIN_LOGGER from '../Utils/logger' // Importar el logger

const logger = MAIN_LOGGER.child({}) // Inicializar el logger

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	logger.info('Creating libsignal repository for authentication state.') //
	const storage: SenderKeyStore = signalStorage(auth)
	return {
		decryptGroupMessage({ group, authorJid, msg }) {
			const senderName = jidToSignalSenderKeyName(group, authorJid)
			const cipher = new GroupCipher(storage, senderName)
			logger.debug(`Attempting to decrypt group message for group: ${group}, author: ${authorJid}`) //
			try {
				const decrypted = cipher.decrypt(msg)
				logger.debug(`Successfully decrypted group message for group: ${group}`) //
				return decrypted
			} catch (error) {
				logger.error(`Error decrypting group message for group: ${group}, author: ${authorJid}. Error: ${error}`) //
				throw error
			}
		},
		async processSenderKeyDistributionMessage({ item, authorJid }) {
			logger.info(`Processing sender key distribution message from author: ${authorJid}`) //
			const builder = new GroupSessionBuilder(storage)
			if(!item.groupId) {
				logger.error('Group ID is required for sender key distribution message but was not provided.') //
				throw new Error('Group ID is required for sender key distribution message')
			}

			const senderName = jidToSignalSenderKeyName(item.groupId, authorJid)

			const senderMsg = new SenderKeyDistributionMessage(
				null,
				null,
				null,
				null,
				item.axolotlSenderKeyDistributionMessage
			)
			const senderNameStr = senderName.toString()
			const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
			
			if (senderKey) {
				logger.debug(`Sender key already exists for ${senderNameStr}.`) //
			} else {
				logger.debug(`Sender key not found for ${senderNameStr}. Building new session.`) //
			}

			await builder.process(senderName, senderMsg)
			logger.info(`Successfully processed sender key distribution message for group: ${item.groupId}`) //
		},
		async loadSession(id: string) {
			const { [id]: session } = await auth.keys.get('session', [id])
			if(session) {
				logger.debug(`Loaded session for ID: ${id}`) //
				return new libsignal.SessionRecord(session)
			}
			logger.debug(`No session found for ID: ${id}`) //
		},
		async storeSession(id: string, session: libsignal.SessionRecord) {
			await auth.keys.set({ session: { [id]: session.serialize() } })
			logger.debug(`Stored session for ID: ${id}`) //
		},
		async removeSession(ids: string[]) {
			await auth.keys.set({ session: Object.fromEntries(ids.map(id => ([id, null]))) })
			logger.debug(`Removed sessions for IDs: ${ids.join(', ')}`) //
		},
		isTrustedIdentity: () => {
			logger.debug('Checking trusted identity (always true in this implementation).') //
			return true
		},
		async loadPreKey(id: number | string) {
			const keyId = id.toString()
			const { [keyId]: key } = await auth.keys.get('pre-key', [keyId])
			if(key) {
				logger.debug(`Loaded pre-key for ID: ${keyId}`) //
				return {
					privKey: Buffer.from(key.private),
					pubKey: Buffer.from(key.public)
				}
			}
			logger.debug(`No pre-key found for ID: ${keyId}`) //
		},
		removePreKey: (id: number) => {
			auth.keys.set({ 'pre-key': { [id]: null } })
			logger.debug(`Removed pre-key for ID: ${id}`) //
		},
		loadSignedPreKey: () => {
			const key = auth.creds.signedPreKey
			logger.debug('Loaded signed pre-key.') //
			return {
				privKey: Buffer.from(key.keyPair.private),
				pubKey: Buffer.from(key.keyPair.public)
			}
		},
		async loadSenderKey(senderKeyName: SenderKeyName) {
			const keyId = senderKeyName.toString()
			const { [keyId]: key } = await auth.keys.get('sender-key', [keyId])
			if(key) {
				logger.debug(`Loaded sender key for name: ${keyId}`) //
				return SenderKeyRecord.deserialize(key)
			}
			logger.debug(`No sender key found for name: ${keyId}. Creating new SenderKeyRecord.`) //
			return new SenderKeyRecord()
		},
		storeSenderKey: async(senderKeyName: SenderKeyName, key: SenderKeyRecord) => {
			const keyId = senderKeyName.toString()
			await auth.keys.set({ 'sender-key': { [keyId]: key.serialize() } })
			logger.debug(`Stored sender key for name: ${keyId}`) //
		}
	}
}

// Internal function from original file, kept as is
function jidToSignalSenderKeyName(groupId: string, authorJid: string): SenderKeyName {
    const { user, device } = jidDecode(authorJid)!;
    if (!device) {
        throw new Error('Author JID must have a device ID for signal sender key name');
    }
    return new SenderKeyName(groupId, user, device);
}

// Internal function from original file, kept as is
function signalStorage(auth: SignalAuthState): SenderKeyStore {
	return {
		getIdentityKeyPair: () => {
			return {
				privKey: Buffer.from(auth.creds.encAuthInfo!.noiseKey.private),
				pubKey: Buffer.from(auth.creds.encAuthInfo!.noiseKey.public)
			}
		},
		getLocalRegistrationId: () => auth.creds.registrationId,
		async isGlobalSignedPreKeyActive() {
			return auth.creds.signedPreKey !== undefined
		},
		async getSignedPreKey(signedPreKeyId: number) {
			const { signedPreKey } = auth.creds
			if (!signedPreKey || signedPreKey.keyId !== signedPreKeyId) {
				return
			}
			return {
				privKey: Buffer.from(signedPreKey.keyPair.private),
				pubKey: Buffer.from(signedPreKey.keyPair.public)
			}
		},
		async getPreKey(keyId: number) {
			const { [keyId]: key } = await auth.keys.get('pre-key', [keyId + ''])
			if (key) {
				return {
					privKey: Buffer.from(key.private),
					pubKey: Buffer.from(key.public)
				}
			}
		},
		async storePreKey(keyId: number, keyPair: libsignal.KeyPair) {
			await auth.keys.set({ 'pre-key': { [keyId + '']: generateSignalPubKey(keyPair) } })
		},
		async storeSignedPreKey(keyId: number, keyPair: libsignal.KeyPair) {
			await auth.keys.set({ 'signed-pre-key': { [keyId + '']: generateSignalPubKey(keyPair) } })
		},
		async getSession(id: string) {
			const { [id]: session } = await auth.keys.get('session', [id])
			if (session) {
				return new libsignal.SessionRecord(session)
			}
		},
		async setSession(id: string, session: libsignal.SessionRecord) {
			await auth.keys.set({ session: { [id]: session.serialize() } })
		},
		async deleteSession(id: string) {
			await auth.keys.set({ session: { [id]: null } })
		},
		async deleteAllSessions(id: string) {
			await auth.keys.set({ session: { [id]: null } })
		},
		async getSenderKey(keyId: SenderKeyName) {
			const { [keyId.toString()]: key } = await auth.keys.get('sender-key', [keyId.toString()])
			if (key) {
				return new libsignal.SenderKeyRecord(key)
			}
		},
		async setSenderKey(keyId: SenderKeyName, record: libsignal.SenderKeyRecord) {
			await auth.keys.set({ 'sender-key': { [keyId.toString()]: record.serialize() } })
		}
	}
}
