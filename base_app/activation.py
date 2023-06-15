from django.utils.crypto import get_random_string
import hashlib

def generate_activation_key(user):
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
    secret_key = get_random_string(6, chars)
    return hashlib.sha256((secret_key + user).encode('utf-8')).hexdigest()