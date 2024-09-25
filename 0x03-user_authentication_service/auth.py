#!/usr/bin/env python3

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User  # Assuming User is defined in user.py

class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self) -> None:
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """
        Hashes a password using bcrypt and returns the hashed password.
        
        :param password: The plain text password.
        :return: The hashed password.
        """
        byte_password = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(byte_password, salt)
        return hashed_password

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user with the provided email and password.
        
        :param email: The user's email.
        :param password: The user's password.
        :return: The newly created user object.
        :raises ValueError: If a user with the given email already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f'User {email} already exists')
        except NoResultFound:
            # Hash the password and add the new user to the database
            hashed_password = self._hash_password(password)
            new_user = self._db.add_user(email=email, hashed_password=hashed_password)
            return new_user
