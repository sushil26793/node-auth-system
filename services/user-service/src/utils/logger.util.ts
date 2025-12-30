// services/user-service/src/utils/logger.util.ts
export const logger = {
  info: (message: string, meta?: any) => {
    console.log(JSON.stringify({ 
      level: 'info', 
      timestamp: new Date().toISOString(), 
      service: 'user-service', 
      message, 
      ...meta 
    }));
  },
  error: (message: string, meta?: any) => {
    console.error(JSON.stringify({ 
      level: 'error', 
      timestamp: new Date().toISOString(), 
      service: 'user-service', 
      message, 
      ...meta 
    }));
  },
  warn: (message: string, meta?: any) => {
    console.warn(JSON.stringify({ 
      level: 'warn', 
      timestamp: new Date().toISOString(), 
      service: 'user-service', 
      message, 
      ...meta 
    }));
  }
};
