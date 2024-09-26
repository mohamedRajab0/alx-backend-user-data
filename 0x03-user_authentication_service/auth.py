#!/usr/bin/env python3

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User  # Assuming User is defined in user.py
import uuid


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
        user = self._db.find_user_by(email=email)
        if user:
            raise ValueError(f'User {email} already exists')
        
        # Hash the password and add the new user to the database
        hashed_password = self._hash_password(password)
        new_user = self._db.add_user(email=email, hashed_password=hashed_password)
        return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates the login credentials for a user.
        
        :param email: The user's email.
        :param password: The user's password.
        :return: True if the credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            if user:
                byte_password = password.encode('utf-8')
                if bcrypt.checkpw(byte_password, user.hashed_password):  # Assuming hashed_password is the attribute
                    return True
        except NoResultFound:
            return False
        return False
    def _generate_uuid(self):
        
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
            """
            Creates a new session for the user identified by the provided email.
            
            :param email: The user's email.
            :return: The session ID as a string.
            :raises ValueError: If the user is not found.
            """
            try:
                # Find the user by email
                user = self._db.find_user_by(email=email)
                
                if user is None:
                    # Raise an error if the user is not found
                    raise ValueError(f"User with email {email} not found")
                
                # Generate a new session ID (UUID)
                session_id = self._generate_uuid()
                
                # Update the user's session_id in the database
                self._db.update_user(user.id, session_id=session_id)
                
                # Return the session ID
                return session_id
            
            except NoResultFound:
                # Raise an error if no user was found in the database
                raise ValueError(f"User with email {email} not found")
    
    def get_user_from_session_id(self, session_id: str):
        """Get user by session ID."""
        if session_id is None:
            return None

        try:
            # Use the public method of self._db to find the user by session_id
            user = self._db.find_user_by(session_id=session_id)
            if user is None:
                return None
            return user
        except Exception as e:
            # Handle any exceptions that might occur during the DB query
            print(f"Error retrieving user from session_id: {e}")
            return None
    def destroy_session(self, user_id: int) -> None:
        """Update the user's session ID to None."""
        try:
            # Retrieve the user by user_id
            user = self._db.find_user_by(id=user_id)
            if user is not None:
                # Update the user's session ID to None
                user.session_id = None
                # Commit the changes to the database
                self._db.save(user)
            return None
        except Exception as e:
            print(f"Error destroying session for user_id {user_id}: {e}")
            return None