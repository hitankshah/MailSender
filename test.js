const { generateOtp, sendOtp, encryptOtp, decryptOtp, validateOtp } = require('./index.js');

async function test() {
  try {
    const testEmail = 'recipient@example.com';
    const otp = generateOtp(6, { upperCaseAlphabets: true, specialChars: true });
    console.log(`Generated OTP: ${otp}`);

    const encryptedOtp = encryptOtp(otp);
    console.log(`Encrypted OTP: ${encryptedOtp}`);

    const decryptedOtp = decryptOtp(encryptedOtp);
    console.log(`Decrypted OTP: ${decryptedOtp}`);

    if (validateOtp(otp, decryptedOtp)) {
      console.log('OTP validation successful!');
    } else {
      console.log('OTP validation failed!');
    }

    await sendOtp(testEmail, otp, {
      attachments: [{ filename: 'test.txt', content: 'Test attachment' }],
      embedImages: true
    });
    console.log('OTP sent successfully!');
  } catch (error) {
    console.error('Error:', error);
  }
}

test();
