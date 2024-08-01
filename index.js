const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const winston = require('winston');
const dotenv = require('dotenv');
const crypto = require('crypto-js');
const path = require('path');
const fs = require('fs');

dotenv.config();

// Setup rate limiter
const rateLimiter = new RateLimiterMemory({
  points: 5, // 5 OTP requests
  duration: 60 * 60, // per hour per email
});

// Setup logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

// Function to generate OTP
function generateOtp(length = 6, options = {}) {
  const { upperCaseAlphabets = false, specialChars = false } = options;
  return otpGenerator.generate(length, {
    upperCaseAlphabets,
    specialChars,
  });
}

// Function to send OTP via email
async function sendOtp(email, otp, options = {}) {
  try {
    await rateLimiter.consume(email); // consume 1 point per request

    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE,
      auth: {
        user: process.env.EMAIL_USER,//your email
        pass: process.env.EMAIL_PASS,//your password
      },
      secure: true, // use TLS/STARTTLS
    });

    const mailOptions = {
      from: `"OTP Verification" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP code is ${otp}`,
      html: `<p>Your OTP code is <strong>${otp}</strong></p>`, // HTML content
      attachments: options.attachments || [], // Attachments
    };

    if (options.embedImages) {
      mailOptions.html += `<img src="cid:image001" />`;
      mailOptions.attachments.push({
        filename: 'image.png',
        path: path.join(__dirname, 'image.png'),
        cid: 'image001'
      });
    }

    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully!');
  } catch (error) {
    logger.error('Error sending OTP:', error);
    throw error; // rethrow to handle it upstream
  }
}

// Function to encrypt OTP
function encryptOtp(otp) {
  return crypto.AES.encrypt(otp, process.env.SECRET_KEY).toString();
}

// Function to decrypt OTP
function decryptOtp(encryptedOtp) {
  const bytes = crypto.AES.decrypt(encryptedOtp, process.env.SECRET_KEY);
  return bytes.toString(crypto.enc.Utf8);
}

// Function to validate OTP
function validateOtp(storedOtp, providedOtp) {
  return storedOtp === providedOtp;
}

// Function to sign email with DKIM
async function signEmail(email) {
  // Implement DKIM signing if necessary
}

// Function to support OAuth2 authentication
async function setupOAuth2() {
  // Implement OAuth2 setup if necessary
}

module.exports = { 
  generateOtp, 
  sendOtp, 
  encryptOtp, 
  decryptOtp, 
  validateOtp,
  signEmail,
  setupOAuth2 
};
