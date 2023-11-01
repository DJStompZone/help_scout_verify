import hashlib
import hmac
import base64
from typing import Union


def generate_hmac_hash(secret: str, data: Union[bytes, bytearray]) -> str:
    """
    Generates an HMAC hash using SHA-1 and returns it as a base64-encoded string.

    Parameters:
    secret (str): The secret key used for generating the hash.
    data (Union[bytes, bytearray]): The data to be hashed.

    Returns:
    str: The base64-encoded hash.
    """
    hasher = hmac.new(secret.encode(), digestmod=hashlib.sha1)
    hasher.update(data)
    return base64.b64encode(hasher.digest()).decode()


def verify_help_scout(secret: str, hs_signature: str, request_data: Union[bytes, bytearray]) -> bool:
    """
    Verifies if a request is from Help Scout by checking the signature.

    Parameters:
    secret (str): The secret key used for generating the hash.
    hs_signature (str): The 'X-HelpScout-Signature' header value from the incoming request.
    request_data (Union[bytes, bytearray]): The raw request body data.

    Returns:
    bool: True if the request is verified to be from Help Scout, False otherwise.
    """
    hash = generate_hmac_hash(secret, request_data)
    return hash == hs_signature
    

def verify_flask(secret: str) -> bool:
    from flask import request
    """
    Verifies a Flask request to check if it's from HelpScout.

    Parameters:
    secret (str): The secret key used for generating the hash.

    Returns:
    bool: True if the request is verified to be from HelpScout, False otherwise.
    """
    hs_signature = request.headers.get('X-HelpScout-Signature')
    request_data = request.get_data()
    
    return verify_help_scout(secret, hs_signature, request_data)


def verify_django(secret: str, req) -> bool:
    from django.http import HttpRequest
    """
    Verifies a Django request to check if it's from HelpScout.

    Parameters:
    secret (str): The secret key used for generating the hash.
    req (HttpRequest): The incoming Django HttpRequest object.

    Returns:
    bool: True if the request is verified to be from HelpScout, False otherwise.
    """
    hs_signature = req.META.get('HTTP_X_HELPSCOUT_SIGNATURE')
    request_data = req.body
    
    return verify_help_scout(secret, hs_signature, request_data)