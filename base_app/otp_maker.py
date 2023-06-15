import pyotp
import string
import random
import datetime

secret_key = ''

def generate_time_based_otp():
    global secret_key
    # Generate random secret key if it's empty
    if not secret_key:
        secret_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    # Create TOTP object with validity of 10 mins
    totp = pyotp.TOTP(secret_key, interval=600)
    # Generate OTP
    otp = totp.now()
    return otp

def is_otp_valid(otp):
    global secret_key
    # Generate current time
    current_time = datetime.datetime.now().timestamp()
    # Create TOTP object
    totp = pyotp.TOTP(secret_key, interval=600)
    # Validate OTP
    is_valid = totp.verify(otp, for_time=current_time)
    return is_valid

