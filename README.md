# mailsender-pro

An advanced npm package to generate and send OTPs via email for verification purposes with enhanced features.

## Features

- **Single Module with Zero Dependencies:** A streamlined package with no external dependencies, making it easy to install and use.
- **Focus on Security:** Designed to avoid RCE (Remote Code Execution) vulnerabilities and other common security issues.
- **Unicode Support:** Handles Unicode characters, including emojis 💪, ensuring global compatibility.
- **Windows Support:** Hassle-free installation and compatibility with Windows environments.
- **HTML and Plain Text Content:** Supports both HTML content and plain text alternatives in emails.
- **Attachments and Embedded Images:** Send emails with attachments and embedded images.
- **Secure Email Delivery:** Utilizes TLS/STARTTLS for secure email transmission.
- **Support for Different Transport Methods:** Flexible configuration for various email transport methods.
- **DKIM Signing:** Optionally sign emails with DKIM for improved email deliverability and authenticity.
- **Custom Plugin Support:** Extend functionality with custom plugins for manipulating email messages.
- **Sane OAuth2 Authentication:** Integrates with OAuth2 for secure authentication.
- **Proxies for SMTP Connections:** Supports SMTP connections through proxies.
- **ES6 Code:** Utilizes modern JavaScript features for a clean and efficient codebase.
- **Autogenerated Email Test Accounts:** Use Ethereal.email to generate test email accounts for development and testing.

## Installation

To install the package, use npm:

```bash
npm install mailsender-pro

Usage
1. Check SMTP Server Details
Make sure you are using the correct SMTP server address and port for your email provider. Here’s a general guide:

Gmail: smtp.gmail.com, port 587 (STARTTLS) or port 465 (SSL)
SendGrid: smtp.sendgrid.net, port 587 (STARTTLS)
Mailgun: smtp.mailgun.org, port 587 (STARTTLS)
Amazon SES: email-smtp.us-east-1.amazonaws.com, port 587 (STARTTLS) or port 465 (SSL)
2. Update Configuration
Update your nodemailer configuration in index.js to use the correct SMTP server and port.

Example for SendGrid:
const transporter = nodemailer.createTransport({
  host: 'smtp.sendgrid.net', // SMTP server host
  port: 587, // Port for STARTTLS
  secure: false, // Use TLS/STARTTLS
  auth: {
    user: 'apikey', // This is the literal string 'apikey'
    pass: process.env.SENDGRID_API_KEY, // Your SendGrid API key
  },
});

Example for Mailgun:

const transporter = nodemailer.createTransport({
  host: 'smtp.mailgun.org',
  port: 587, // Port for STARTTLS
  secure: false, // Use TLS/STARTTLS
  auth: {
    user: process.env.MAILGUN_USER,
    pass: process.env.MAILGUN_PASS,
  },
});

Example for Amazon SES:

const transporter = nodemailer.createTransport({
  host: 'email-smtp.us-east-1.amazonaws.com',
  port: 587, // Port for STARTTLS
  secure: false, // Use TLS/STARTTLS
  auth: {
    user: process.env.AWS_SES_USER,
    pass: process.env.AWS_SES_PASS,
  },
});

3. Test Connectivity
To ensure your SMTP server is reachable, you can manually test the connection using tools like telnet or openssl:

For telnet:
telnet smtp.sendgrid.net 587

For openssl:
openssl s_client -connect smtp.sendgrid.net:465

# Generate OTP
Generate a One-Time Password (OTP):
const { generateOtp } = require('mailsender-pro');

const otp = generateOtp(6, { upperCaseAlphabets: true, specialChars: true });
console.log(`Generated OTP: ${otp}`);

# Encrypt OTP
Encrypt an OTP for secure storage:

const { encryptOtp } = require('mailsender-pro');

const encryptedOtp = encryptOtp('123456');
console.log(`Encrypted OTP: ${encryptedOtp}`);

# Decrypt OTP
Decrypt an OTP for verification:

const { decryptOtp } = require('mailsender-pro');

const decryptedOtp = decryptOtp('encryptedOtpString');
console.log(`Decrypted OTP: ${decryptedOtp}`);

# Validate OTP
Validate if the provided OTP matches the generated OTP:
Validate OTP
Validate if the provided OTP matches the generated OTP:

# Send OTP

Send an OTP via email:
const { sendOtp } = require('mailsender-pro');

const mailOptions = {
  to: 'recipient@example.com',
  subject: 'Your OTP Code',
  otpLength: 6,
  customMessage: 'Your OTP code is {otp}. This code is valid for 10 minutes.',
  otpExpiresIn: 10,
  html: '<h1>Your OTP Code</h1><p>{otp}</p>',
  attachments: [
    {
      filename: 'test.txt',
      content: 'This is a test file'
    }
  ],
  embedImages: true
};

sendOtp('recipient@example.com', '123456', mailOptions)
  .then(() => console.log('OTP sent successfully!'))
  .catch(error => console.error('Error sending OTP:', error));


# Development
Running Tests
To run the tests for the package, use:

npm test

#Contributing
Fork the repository.
Create a new branch (git checkout -b feature/your-feature).
Make your changes.
Commit your changes (git commit -am 'Add new feature').
Push to the branch (git push origin feature/your-feature).
Create a new Pull Request.

#Authors
Hitank Shah - Hitankjain@gmail.com
Maharshi Agrawal - maharshiagrawal93@gmail.com
Saksham Jain - jainsaksham0101001@gmail.com
Vedant Dongare - dongrevedant79@gmail.com