import MAIN_LOGGER from '../../Utils/logger' // Importar el logger

const logger = MAIN_LOGGER.child({}) // Inicializar el logger

interface QueueJob<T> {
	awaitable: () => Promise<T>
	resolve: (value: T | PromiseLike<T>) => void
	reject: (reason?: unknown) => void
}

const _queueAsyncBuckets = new Map<string | number, Array<QueueJob<any>>>()
const _gcLimit = 10000

async function _asyncQueueExecutor(queueName: string | number, queue: Array<QueueJob<any>>, cleanup: () => void): Promise<void> {
	logger.debug(`Queue executor started for bucket: ${queueName}. Current queue length: ${queue.length}.`) //
	let offt = 0
	// eslint-disable-next-line no-constant-condition
	while (true) {
		const limit = Math.min(queue.length, _gcLimit)
		for (let i = offt; i < limit; i++) {
			const job = queue[i]
			logger.debug(`Executing job ${i + 1} for bucket: ${queueName}.`) //
			try {
				job.resolve(await job.awaitable())
				logger.info(`Job ${i + 1} completed successfully for bucket: ${queueName}.`) //
			} catch (e) {
				job.reject(e)
				logger.error(`Job ${i + 1} failed for bucket: ${queueName}: ${e}.`) //
			}
		}

		if(limit < queue.length) {
			if(limit >= _gcLimit) {
				logger.debug(`Splicing queue for bucket: ${queueName}. Removing ${limit} jobs.`) //
				queue.splice(0, limit)
				offt = 0
			} else {
				offt = limit
			}
		} else {
			break
		}
	}

	cleanup()
	logger.debug(`Queue executor finished for bucket: ${queueName}.`) //
}

export default function queueJob<T>(bucket: string | number, awaitable: () => Promise<T>): Promise<T> {
	logger.debug(`Adding new job to queue bucket: ${bucket}.`) //
	// Skip name assignment since it's readonly in strict mode
	if(typeof bucket !== 'string' && typeof bucket !== 'number') { // Mejorar la verificación de tipo
		logger.warn(`Unhandled bucket type: ${typeof bucket}, value: ${bucket}. Using as is.`) // console.warn -> logger.warn
	}

	let inactive = false
	let queue = _queueAsyncBuckets.get(bucket)
	if(!queue) {
		queue = []
		_queueAsyncBuckets.set(bucket, queue)
		inactive = true
	}

	return new Promise((resolve, reject) => {
		queue!.push({ awaitable, resolve, reject })
		if(inactive) {
			_asyncQueueExecutor(
				bucket,
				queue!,
				() => _queueAsyncBuckets.delete(bucket)
			)
		}
	})
}
