import { Kafka } from "kafkajs";
export const kafka = new Kafka({
    clientId: "auth-service",
    brokers: (process.env.KAFKA_BROKERS || 'kafka:9092').split(','),
    ssl: process.env.KAFKA_SSL === "true" ? {} : undefined,
    sasl: process.env.KAFKA_SASL_USERNAME ?
        {
            mechanism: 'plain', username: process.env.KAFKA_SASL_USERNAME,
            password: process.env.KAFKA_SASL_PASSWORD
        }
        : undefined
});
