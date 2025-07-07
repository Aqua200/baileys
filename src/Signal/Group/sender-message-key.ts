import { deriveSecrets } from 'libsignal/src/crypto';
import logger from '../Utils/logger'; // Importa el logger desde la ruta asumida

export class SenderMessageKey {
    private readonly iteration: number;
    private readonly iv: Uint8Array;
    private readonly cipherKey: Uint8Array;
    private readonly seed: Uint8Array;

    constructor(iteration: number, seed: Uint8Array) {
        // --- Mejoras: Validación de entrada ---
        if (typeof iteration !== 'number' || iteration < 0) {
            throw new Error('Iteration must be a non-negative number.');
        }
        if (!(seed instanceof Uint8Array) || seed.length === 0) {
            throw new Error('Seed must be a non-empty Uint8Array.');
        }

        const derivative = deriveSecrets(seed, Buffer.alloc(32), Buffer.from('WhisperGroup'));
        const keys = new Uint8Array(32);
        keys.set(new Uint8Array(derivative[0].slice(16)));
        keys.set(new Uint8Array(derivative[1].slice(0, 16)), 16);

        this.iv = Buffer.from(derivative[0].slice(0, 16));
        this.cipherKey = Buffer.from(keys.buffer);
        this.iteration = iteration;
        this.seed = new Uint8Array(seed); // --- Mejora: Almacenar una copia para asegurar inmutabilidad ---

        // --- Método "lid" (Registro de eventos) ---
        // Se añade un log de depuración para indicar la creación de una instancia de SenderMessageKey.
        // Incluye la iteración y la longitud de la semilla para evitar el log de datos sensibles directamente.
        logger.debug({ iteration: this.iteration, seedLength: this.seed.length }, 'SenderMessageKey created');
    }

    public getIteration(): number {
        return this.iteration;
    }

    public getIv(): Uint8Array {
        return this.iv;
    }

    public getCipherKey(): Uint8Array {
        return this.cipherKey;
    }

    public getSeed(): Uint8Array {
        return new Uint8Array(this.seed); // --- Mejora: Devolver una copia para prevenir modificaciones externas ---
    }
}
