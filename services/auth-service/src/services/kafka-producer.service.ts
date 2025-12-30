import { kafka } from "../config/kafka.js";
import { logger } from "../utils/logger.util.js";
import { ProducerRecord, RecordMetadata } from "kafkajs"; // Import for types

const producer = kafka.producer();

export class KafkaProducer {
    async connect(): Promise<void> {
        // Log connection attempt/success
        logger.info("Attempting to connect Kafka Producer...");
        await producer.connect();
        logger.info("Kafka Producer successfully connected.");
    }

    /**
     * Publishes an event to a Kafka topic.
     * @param topic The target Kafka topic.
     * @param payload The message content (object).
     * @param key Optional key for guaranteed message ordering (e.g., user ID).
     */
    async publishEvent(topic: string, payload: any, key?: string): Promise<RecordMetadata[]> {
        const messagePayload: ProducerRecord = {
            topic,
            messages: [
                {
                    value: JSON.stringify(payload),
                    key: key, 
                }
            ],
        };

        try {
            const result = await producer.send(messagePayload);
            
            const firstResult = result[0];
            logger.info('Kafka event published successfully', {
                topic,
                key: key || 'none',
                partition: firstResult.partition,
                offset: firstResult.offset,
                timestamp: new Date().toISOString()
            });

            return result; // Return the metadata if needed by the caller
            
        } catch (err: any) {
            const message = err?.message || JSON.stringify(err);
            logger.error('Kafka publish failed', { 
                topic, 
                key: key || 'none',
                error: message 
            });
            // Re-throw the error to allow the calling service logic to handle failure
            throw new Error(`Failed to publish event to topic ${topic}: ${message}`);
        }
    }
}

export const kafkaProducer = new KafkaProducer();