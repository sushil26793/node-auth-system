import fs from 'fs/promises';
import path from 'path';
import handlebars from 'handlebars';
import { transporter } from '../config/email';
import { logger } from '../utils/logger.util';




export class EmailService {

    private async loadTemplate(templateName: string, data: any): Promise<string> {
        const filePath = path.join(__dirname, "../templates", `${templateName}.html`);
        const source = await fs.readFile(filePath, 'utf-8');
        const template = handlebars.compile(source);
        return template(data)
    }

    async sendVerificationEmail(to: string, token: string) {
        try {
            const verificationLink = `${process.env.FRONTEND_URL}/verify?token=${token}`;
            const html = await this.loadTemplate('verification', { verificationLink });
            const sendResult = await transporter.sendMail({
                from: process.env.SMTP_FROM || '"Auth System" <noreply@example.com>',
                to,
                subject: "Verify your email",
                html
            })
            logger.info('Verification email sent', { email: to });
            return sendResult;

        } catch (error: any) {
            logger.error('Failed to send verification email', { error: error.message });
            throw error;
        }
    }

    async sendPasswordResetEmail(to: string, token: string) {
        try {
            const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
            const html = await this.loadTemplate('password-reset', { resetLink });
            const result = await transporter.sendMail({
                from: process.env.SMTP_FROM || '"Auth System" <noreply@example.com>',
                to,
                subject: "Reset your password",
                html

            })
            logger.info('Password reset email sent', { email: to });
            return result;

        } catch (error: any) {
            logger.error('Failed to send password reset email', { error: error.message });
            throw error;
        }
    }
}