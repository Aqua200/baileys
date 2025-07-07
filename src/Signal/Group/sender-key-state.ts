import { SenderChainKey } from './sender-chain-key';
import { SenderMessageKey } from './sender-message-key';
import MAIN_LOGGER from '../../Utils/logger'; // Importar el logger

const logger = MAIN_LOGGER.child({}); // Inicializar el logger para este módulo

/**
 * Define la estructura para la clave de cadena del remitente.
 */
interface SenderChainKeyStructure {
    iteration: number;
    seed: Uint8Array;
}

/**
 * Define la estructura para la clave de firma del remitente.
 */
interface SenderSigningKeyStructure {
    public: Uint8Array;
    private?: Uint8Array;
}

/**
 * Define la estructura para una clave de mensaje del remitente.
 */
interface SenderMessageKeyStructure {
    iteration: number;
    seed: Uint8Array;
}

/**
 * Define la estructura completa de un estado de clave de remitente.
 */
export interface SenderKeyStateStructure {
    senderKeyId: number;
    senderChainKey: SenderChainKeyStructure;
    senderSigningKey: SenderSigningKeyStructure;
    senderMessageKeys: SenderMessageKeyStructure[];
}

/**
 * Representa el estado de una clave de remitente (Sender Key) para una sesión de grupo.
 * Gestiona la cadena de claves, las claves de firma y las claves de mensaje.
 * También implementa el "lid" (límite) para las claves de mensaje.
 */
export class SenderKeyState {
    // MAX_MESSAGE_KEYS ahora es una propiedad de instancia y configurable
    private readonly MAX_MESSAGE_KEYS: number;
    private readonly senderKeyStateStructure: SenderKeyStateStructure;

    /**
     * Constructor para la clase SenderKeyState.
     * Permite crear un nuevo estado de clave de remitente o inicializarlo desde una estructura existente.
     * @param id - El ID de la clave de remitente. Obligatorio si no se proporciona `senderKeyStateStructure`.
     * @param iteration - La iteración inicial de la cadena de claves. Obligatorio si no se proporciona `senderKeyStateStructure`.
     * @param chainKey - La semilla inicial de la clave de cadena. Obligatorio si no se proporciona `senderKeyStateStructure`.
     * @param signatureKeyPair - Un par de claves de firma (pública y privada).
     * @param signatureKeyPublic - La clave pública de firma. Usado si `signatureKeyPair` no está presente.
     * @param signatureKeyPrivate - La clave privada de firma. Usado si `signatureKeyPair` no está presente.
     * @param senderKeyStateStructure - Una estructura de estado de clave de remitente existente para inicializar.
     * @param maxMessageKeys - El número máximo de claves de mensaje a mantener. Por defecto es 2000.
     * @throws {Error} Si faltan parámetros obligatorios al crear un nuevo estado.
     */
    constructor(
        id?: number | null,
        iteration?: number | null,
        chainKey?: Uint8Array | null,
        signatureKeyPair?: { public: Uint8Array; private: Uint8Array } | null,
        signatureKeyPublic?: Uint8Array | null,
        signatureKeyPrivate?: Uint8Array | null,
        senderKeyStateStructure?: SenderKeyStateStructure | null,
        maxMessageKeys: number = 2000 // Configurable: Límite para el "lid"
    ) {
        this.MAX_MESSAGE_KEYS = maxMessageKeys;
        logger.debug({ id, iteration, maxMessageKeys }, 'Initializing SenderKeyState'); // lid

        if (senderKeyStateStructure) {
            this.senderKeyStateStructure = senderKeyStateStructure;
            logger.debug({ senderKeyId: senderKeyStateStructure.senderKeyId }, 'SenderKeyState initialized from existing structure.'); // lid
        } else {
            // Validaciones al crear un nuevo estado
            if (id === null || id === undefined) {
                logger.error('SenderKeyId is null or undefined when creating a new SenderKeyState.'); // lid
                throw new Error('SenderKeyId must be provided when creating a new SenderKeyState.');
            }
            if (iteration === null || iteration === undefined) {
                logger.error(`Iteration is null or undefined for SenderKeyId: ${id}.`); // lid
                throw new Error('Iteration must be provided when creating a new SenderKeyState.');
            }
            if (!chainKey || chainKey.length === 0) {
                logger.error(`ChainKey is empty or null for SenderKeyId: ${id}.`); // lid
                throw new Error('ChainKey must be provided when creating a new SenderKeyState.');
            }
            if (!signatureKeyPair && (!signatureKeyPublic || !signatureKeyPrivate)) {
                logger.error(`SignatureKey is missing for SenderKeyId: ${id}.`); // lid
                throw new Error('SignatureKey must be provided when creating a new SenderKeyState.');
            }

            if (signatureKeyPair) {
                signatureKeyPublic = signatureKeyPair.public;
                signatureKeyPrivate = signatureKeyPair.private;
            }

            const senderChainKeyStructure: SenderChainKeyStructure = {
                iteration: iteration || 0,
                seed: chainKey || Buffer.alloc(0),
            };

            const senderSigningKeyStructure: SenderSigningKeyStructure = {
                public: signatureKeyPublic!,
                private: signatureKeyPrivate!,
            };

            this.senderKeyStateStructure = {
                senderKeyId: id,
                senderChainKey: senderChainKeyStructure,
                senderSigningKey: senderSigningKeyStructure,
                senderMessageKeys: [],
            };
            logger.debug({ senderKeyId: id }, 'New SenderKeyState created.'); // lid
        }
    }

    /**
     * Obtiene el ID de la clave de remitente.
     * @returns {number} El ID de la clave de remitente.
     */
    public getKeyId(): number {
        return this.senderKeyStateStructure.senderKeyId;
    }

    /**
     * Obtiene la clave de cadena del remitente.
     * @returns {SenderChainKey} La clave de cadena actual.
     */
    public getSenderChainKey(): SenderChainKey {
        return new SenderChainKey(
            this.senderKeyStateStructure.senderChainKey.iteration,
            this.senderKeyStateStructure.senderChainKey.seed
        );
    }

    /**
     * Establece una nueva clave de cadena para el remitente.
     * @param senderChainKey - La nueva instancia de SenderChainKey.
     */
    public setSenderChainKey(senderChainKey: SenderChainKey): void {
        this.senderKeyStateStructure.senderChainKey = {
            iteration: senderChainKey.getIteration(),
            seed: senderChainKey.getSeed(),
        };
        logger.debug({ senderKeyId: this.getKeyId(), newIteration: senderChainKey.getIteration() }, 'SenderChainKey updated.'); // lid
    }

    /**
     * Obtiene la clave pública de firma del remitente.
     * @returns {Uint8Array} La clave pública de firma.
     */
    public getSigningKeyPublic(): Uint8Array {
        const publicKey = this.senderKeyStateStructure.senderSigningKey.public;
        // La validación de Buffer.from(publicKey || []) asegura que siempre sea un Buffer
        return publicKey instanceof Buffer ? publicKey : Buffer.from(publicKey || []);
    }

    /**
     * Obtiene la clave privada de firma del remitente.
     * @returns {Buffer | undefined} La clave privada de firma, o `undefined` si no está disponible.
     */
    public getSigningKeyPrivate(): Buffer | undefined {
        const privateKey = this.senderKeyStateStructure.senderSigningKey.private;
        if (!privateKey) {
            return undefined;
        }
        // La validación de Buffer.from(privateKey || []) asegura que siempre sea un Buffer
        return privateKey instanceof Buffer ? privateKey : Buffer.from(privateKey || []);
    }

    /**
     * Verifica si existe una clave de mensaje para una iteración dada.
     * @param iteration - La iteración de la clave de mensaje a buscar.
     * @returns {boolean} `true` si la clave existe, `false` en caso contrario.
     */
    public hasSenderMessageKey(iteration: number): boolean {
        return this.senderKeyStateStructure.senderMessageKeys.some(key => key.iteration === iteration);
    }

    /**
     * Añade una nueva clave de mensaje del remitente.
     * Si el número de claves excede `MAX_MESSAGE_KEYS`, las claves más antiguas son eliminadas (lid).
     * @param senderMessageKey - La instancia de SenderMessageKey a añadir.
     */
    public addSenderMessageKey(senderMessageKey: SenderMessageKey): void {
        this.senderKeyStateStructure.senderMessageKeys.push({
            iteration: senderMessageKey.getIteration(),
            seed: senderMessageKey.getSeed(),
        });
        logger.debug({ senderKeyId: this.getKeyId(), iteration: senderMessageKey.getIteration() }, 'SenderMessageKey added.'); // lid

        // Aplicar el "lid"
        if (this.senderKeyStateStructure.senderMessageKeys.length > this.MAX_MESSAGE_KEYS) {
            const removedKeysCount = this.senderKeyStateStructure.senderMessageKeys.length - this.MAX_MESSAGE_KEYS;
            this.senderKeyStateStructure.senderMessageKeys.splice(0, removedKeysCount);
            logger.debug({ senderKeyId: this.getKeyId(), removedKeys: removedKeysCount }, `Trimmed SenderMessageKeys to ${this.MAX_MESSAGE_KEYS}.`); // lid
        }
    }

    /**
     * Elimina una clave de mensaje del remitente por su iteración.
     * @param iteration - La iteración de la clave de mensaje a eliminar.
     * @returns {SenderMessageKey | null} La clave de mensaje eliminada, o `null` si no se encontró.
     */
    public removeSenderMessageKey(iteration: number): SenderMessageKey | null {
        const index = this.senderKeyStateStructure.senderMessageKeys.findIndex(key => key.iteration === iteration);

        if (index !== -1) {
            const messageKey = this.senderKeyStateStructure.senderMessageKeys[index];
            this.senderKeyStateStructure.senderMessageKeys.splice(index, 1);
            logger.debug({ senderKeyId: this.getKeyId(), iteration }, 'SenderMessageKey removed.'); // lid
            return new SenderMessageKey(messageKey.iteration, messageKey.seed);
        }
        logger.debug({ senderKeyId: this.getKeyId(), iteration }, 'SenderMessageKey not found for removal.'); // lid
        return null;
    }

    /**
     * Recorta las claves de mensaje a la longitud máxima configurada (`MAX_MESSAGE_KEYS`).
     * Este método puede ser llamado externamente para forzar la limpieza.
     */
    public trimMessageKeys(): void {
        if (this.senderKeyStateStructure.senderMessageKeys.length > this.MAX_MESSAGE_KEYS) {
            const removedCount = this.senderKeyStateStructure.senderMessageKeys.length - this.MAX_MESSAGE_KEYS;
            this.senderKeyStateStructure.senderMessageKeys.splice(0, removedCount);
            logger.debug({ senderKeyId: this.getKeyId(), removed: removedCount }, `Manually trimmed message keys.`); // lid
        }
    }

    /**
     * Obtiene la estructura interna completa del estado de la clave de remitente.
     * @returns {SenderKeyStateStructure} La estructura del estado de la clave de remitente.
     */
    public getStructure(): SenderKeyStateStructure {
        return this.senderKeyStateStructure;
    }
}
