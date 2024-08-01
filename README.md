# Advanced OTP Email Verification

An advanced npm package to generate and send OTPs via email for verification purposes with enhanced features.

## Features

- Single module with zero dependencies
- Focus on security to avoid RCE vulnerabilities
- Unicode support, including emoji 💪
- Windows support with hassle-free installation
- HTML content and plain text alternative
- Support for attachments and embedded image attachments
- Secure email delivery using TLS/STARTTLS
- Support for different transport methods
- DKIM signing for messages
- Custom plugin support for manipulating messages
- Sane OAuth2 authentication
- Proxies for SMTP connections
- ES6 code for modern JavaScript features
- Autogenerated email test accounts from Ethereal.email

## Installation

```bash
npm install mailsender-pro


1. Check SMTP Server Details
Make sure you are using the correct SMTP server address and port for your email provider. Here’s a general guide:

Gmail: smtp.gmail.com, port 587 (STARTTLS) or port 465 (SSL)
SendGrid: smtp.sendgrid.net, port 587 (STARTTLS)
Mailgun: smtp.mailgun.org, port 587 (STARTTLS)
Amazon SES: email-smtp.us-east-1.amazonaws.com, port 587 (STARTTLS) or port 465 (SSL)
2. Update Configuration
Update your nodemailer configuration in index.js to use the correct SMTP server and port


Here’s an example of how to update it for SendGrid:

const transporter = nodemailer.createTransport({
  host: 'smtp.sendgrid.net', // SMTP server host
  port: 587, // Port for STARTTLS
  secure: false, // Use TLS/STARTTLS
  auth: {
    user: 'apikey', // This is the literal string 'apikey'
    pass: process.env.SENDGRID_API_KEY, // Your SendGrid API key
  },
});

For Mailgun:

const transporter = nodemailer.createTransport({
  host: 'smtp.mailgun.org',
  port: 587, // Port for STARTTLS
  secure: false, // Use TLS/STARTTLS
  auth: {
    user: process.env.MAILGUN_USER,
    pass: process.env.MAILGUN_PASS,
  },
});

For Amazon SES:

const transporter = nodemailer.createTransport({
  host: 'email-smtp.us-east-1.amazonaws.com',
  port: 587, // Port for STARTTLS
  secure: false, // Use TLS/STARTTLS
  auth: {
    user: process.env.AWS_SES_USER,
    pass: process.env.AWS_SES_PASS,
  },
});
4. Test Connectivity
Try to test the SMTP connection manually using a tool like telnet or openssl:

bash
telnet smtp.sendgrid.net 587
or

bash

openssl s_client -connect smtp.sendgrid.net:465
