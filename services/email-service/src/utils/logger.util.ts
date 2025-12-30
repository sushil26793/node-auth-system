export const logger = {
  info: (message: string, meta?: any) => {
    console.log(JSON.stringify({ 
      level: 'info', 
      timestamp: new Date().toISOString(), 
      service: 'email-service', 
      message, 
      ...meta 
    }));
  },
  error: (message: string, meta?: any) => {
    console.error(JSON.stringify({ 
      level: 'error', 
      timestamp: new Date().toISOString(), 
      service: 'email-service', 
      message, 
      ...meta 
    }));
  }
};
