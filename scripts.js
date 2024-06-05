function dec2hex(s) {
    return (s < 15.5 ? '0' : '') + Math.round(s).toString(16);
}

function hex2dec(s) {
    return parseInt(s, 16);
}

function leftpad(str, len, pad) {
    if (len + 1 >= str.length) {
        str = Array(len + 1 - str.length).join(pad) + str;
    }
    return str;
}

function base32tohex(base32) {
    const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    let hex = "";

    for (let i = 0; i < base32.length; i++) {
        let val = base32chars.indexOf(base32.charAt(i).toUpperCase());
        bits += leftpad(val.toString(2), 5, '0');
    }

    for (let i = 0; i + 4 <= bits.length; i += 4) {
        let chunk = bits.substr(i, 4);
        hex = hex + parseInt(chunk, 2).toString(16);
    }

    return hex;
}

function generateOTP(secret) {
    try {
        const key = base32tohex(secret);
        const epoch = Math.round(new Date().getTime() / 1000.0);
        const time = leftpad(dec2hex(Math.floor(epoch / 30)), 16, '0');

        const hmacObj = new jsSHA('SHA-1', 'HEX');
        hmacObj.setHMACKey(key, 'HEX');
        hmacObj.update(time);
        const hmac = hmacObj.getHMAC('HEX');

        const offset = hex2dec(hmac.substring(hmac.length - 1));
        const otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) + '';
        return otp.substr(otp.length - 6, 6);
    } catch (error) {
        console.error("Error generating OTP:", error);
        return null;
    }
}

function isValidBase32(str) {
    const base32Regex = /^[A-Z2-7]+=*$/;
    return base32Regex.test(str);
}

document.getElementById('auth-form').addEventListener('submit', function (e) {
    e.preventDefault();
    const secret = document.getElementById('secret').value.trim().toUpperCase();
    const errorMessage = document.getElementById('error-message');
    const otpDisplay = document.getElementById('otp-display');

    if (!isValidBase32(secret)) {
        errorMessage.textContent = 'Invalid secret key. It should only contain Base32 characters (A-Z, 2-7).';
        otpDisplay.textContent = '';
        return;
    }

    if (secret.length % 8 !== 0) {
        errorMessage.textContent = 'Invalid secret key length. It should be a multiple of 8.';
        otpDisplay.textContent = '';
        return;
    }

    const otp = generateOTP(secret);
    if (otp) {
        otpDisplay.textContent = otp;
        errorMessage.textContent = '';
    } else {
        errorMessage.textContent = 'Failed to generate OTP. Please check your secret key.';
        otpDisplay.textContent = '';
    }
});
