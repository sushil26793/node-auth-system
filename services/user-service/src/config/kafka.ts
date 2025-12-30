import { KafkaConfig } from 'kafkajs';

export const kafkaConfig: KafkaConfig = {
  clientId: 'user-service',
  brokers: (process.env.KAFKA_BROKERS || 'kafka:9092').split(','),
  ssl: process.env.KAFKA_SSL === 'true' ? {} : undefined,
  sasl: process.env.KAFKA_SASL_USERNAME ? {
    mechanism: 'plain',
    username: process.env.KAFKA_SASL_USERNAME as string,
    password: process.env.KAFKA_SASL_PASSWORD as string
  } : undefined,
  retry: {
    initialRetryTime: 100,
    retries: 8
  }
};
