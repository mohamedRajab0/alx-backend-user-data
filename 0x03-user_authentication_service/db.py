#!/usr/bin/env python3

"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError

from user import Base, User


class DB:
    """DB class to manage database connection and user operations
    """

    def __init__(self) -> None:
        """Initialize a new DB instance"""
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)  # Reset database on initialization
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object"""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a new user to the database"""
        user = User(email=email, hashed_password=hashed_password)
        session = self._session
        session.add(user)
        session.commit()
        return user

    def find_user_by(self, **kwargs):
        """
        Find a user by arbitrary keyword arguments.
        
        :param kwargs: Arbitrary keyword arguments for filtering the query.
        :return: User object if found.
        :raises NoResultFound: If no user matches the filtering criteria.
        :raises InvalidRequestError: If the query is invalid.
        """
        try:
            session = self._session  # Ensure session is accessed correctly
            user = session.query(User).filter_by(**kwargs).first()
            
            if user is None:
                return None  # No need to raise NoResultFound
            
            return user
        
        except InvalidRequestError as e:
            raise InvalidRequestError("Invalid query arguments provided") from e



    def update_user(self, user_id: int, **kwargs) -> User:
        """
        Update user attributes by user ID.
        
        :param user_id: ID of the user to update.
        :param kwargs: Attributes to update.
        :return: The updated user object.
        """
        user = self.find_user_by(id=user_id)  # Find the user by ID
        session = self._session  # Correctly initialize session

        for key, value in kwargs.items():
            setattr(user, key, value)  # Dynamically update user attributes
        
        session.commit()
        return user
