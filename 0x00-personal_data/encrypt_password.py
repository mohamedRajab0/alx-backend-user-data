#!/usr/bin/env python3
""" script to hash passwords
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes the given password using bcrypt.
    Args:
        password (str): The password to be hashed.
    Returns:
        bytes: The hashed password.
    """
    byt_psd = password.encode()
    salted = bcrypt.hashpw(byt_psd, bcrypt.gensalt())
    return salted

def  is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check whether a password is valid
    Args:
        hashed_password (bytes): hashed password
        password (str): password in string
    Return:
        bool
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
