import { Kafka, KafkaConfig } from "kafkajs";


export const kafkaConfig: KafkaConfig = {
    clientId: 'email-service',
    brokers: (process.env.KAFKA_BROKERS || 'localhost:9092').split(','),
    retry: {
        initialRetryTime: 100,
        retries: 8
    }
}


export const kafka = new Kafka(kafkaConfig);