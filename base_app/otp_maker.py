import pyotp
import base64
import os

# Generate random secret key
secret_key = base64.b32encode(os.urandom(10)).decode()

def generate_time_based_otp():
    global secret_key
    # Create TOTP object with validity of 10 mins
    totp = pyotp.TOTP(secret_key, interval=600)
    # Generate OTP
    otp = totp.now()
    return otp

def is_otp_valid(otp):
    global secret_key
    # Create TOTP object
    totp = pyotp.TOTP(secret_key, interval=600)
    # Validate OTP
    is_valid = totp.verify(otp)
    return is_valid

