import mongoose, { Schema } from 'mongoose';
const AuditLogSchema = new Schema({
    userId: { type: String, required: true, index: true },
    action: { type: String, required: true, index: true },
    metadata: { type: Schema.Types.Mixed },
    timestamp: { type: Date, default: Date.now }
});
// TTL index - auto-delete logs older than 90 days
AuditLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 7776000 });
export const AuditLog = mongoose.model('AuditLog', AuditLogSchema);
