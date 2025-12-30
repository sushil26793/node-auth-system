
import mongoose, { Document, Schema } from 'mongoose';

/**
 * Audit log for security and compliance
 */
export interface IAuditLog extends Document {
  userId: string;
  action: string;
  metadata: any;
  timestamp: Date;
}

const AuditLogSchema = new Schema<IAuditLog>({
  userId: { type: String, required: true, index: true },
  action: { type: String, required: true, index: true },
  metadata: { type: Schema.Types.Mixed },
  timestamp: { type: Date, default: Date.now }
});

// TTL index - auto-delete logs older than 90 days
AuditLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 7776000 });

export const AuditLog = mongoose.model<IAuditLog>('AuditLog', AuditLogSchema);
