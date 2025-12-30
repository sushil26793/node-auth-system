
const mockSendMail = jest.fn().mockResolvedValue({ messageId: 'test-id' });

jest.mock('../src/config/email', () => ({
    transporter: {
        sendMail: mockSendMail,
    },
}));

import { transporter } from '../src/config/email';
import { EmailService } from '../src/services/email.service';

describe('Email service', () => {
    let emailService: EmailService;

    beforeEach(() => {
        emailService = new EmailService();
        jest.clearAllMocks();
    })

    it('should send verification email with correct link', async () => {
        process.env.FRONTEND_URL = 'http://localhost:3000';
        const email = 'sushilsatyarthi@gmail.com';
        const token = 'abc-123';

        await emailService.sendVerificationEmail(email, token);
        expect(transporter.sendMail).toHaveBeenCalledTimes(1);
        const callArgs = (transporter.sendMail as jest.Mock).mock.calls[0][0];
        expect(callArgs.to).toBe(email);
        expect(callArgs.subject).toContain('Verify');
        // expect(callArgs.html).toContain('http://localhost:3000/verify?token=abc-123');

    });

    it('send password reset email', async () => {   
            process.env.FRONTEND_URL = 'http://localhost:3000';
            const email = 'sushilsatyarthi@gmail.com';
            const token='reset-token-xyz';
            await emailService.sendPasswordResetEmail(email,token);
            const callArgs = (transporter.sendMail as jest.Mock).mock.calls[0][0];
            expect(callArgs.html).toContain('http://localhost:3000/reset-password?token=reset-token-xyz');
    });
});




// // send real mails 
// import { EmailService } from '../src/services/email.service';
// import { transporter } from '../src/config/email';

// // Load environment variables for nodemailer authentication and URL generation
// import "dotenv/config";

// // --- Configuration ---
// // ⚠️ Replace this with a real email address you can check!
// const RECIPIENT_EMAIL = 'sushilsatyarthi@gmail.com';
// const TEST_TOKEN = 'test-token-123456';

// describe('EMAIL INTEGRATION TEST (Real Send)', () => {
//     let emailService: EmailService;

//     jest.setTimeout(20000);

//     beforeAll(() => {
//         if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
//             throw new Error("SMTP_USER and SMTP_PASS must be set in .env for integration test.");
//         }
//         emailService = new EmailService();
//     });

//     it('should successfully send a verification email to a real address', async () => {
//         // Setup environment variables needed by the service methods
//         process.env.FRONTEND_URL = 'http://localhost:3000';

//         try {
//             console.log(`Attempting to send real email to: ${RECIPIENT_EMAIL}`);
//             const response = await emailService.sendVerificationEmail(RECIPIENT_EMAIL, TEST_TOKEN);

//             console.log("Email send response:0000000000", response);
//             expect(response).toBeDefined();
//             expect(response).toHaveProperty('messageId');
//             expect(response.messageId).toBeTruthy();

//             console.log(`✅ Email sent successfully! Message ID: ${response.messageId}`);

//         } catch (error) {
//             console.error("❌ Email sending failed. Check your .env file and App Password.", error);
//             fail('Email service failed to send the email. Check logs.');
//         }
//     });


//     it('send password reset email', async () => {
//         process.env.FRONTEND_URL = 'http://localhost:3000';
//         const email = 'sushilsatyarthi@gmail.com';
//         const token = 'reset-token-xyz';
//         const response = await emailService.sendPasswordResetEmail(email, token)
//         expect(response).toBeDefined();
//         expect(response).toHaveProperty('messageId');
//         expect(response.messageId).toBeTruthy();

//     })



// });

