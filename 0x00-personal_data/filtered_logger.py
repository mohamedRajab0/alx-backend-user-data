#!/usr/bin/env python3
"""This module provides a logger with redaction for sensitive data.
The module defines a RedactingFormatter class.
This formatter is used to redact sensitive data.
Example usage:
    logger = get_logger()
    logger.info("User logged in: name=john, email=john@example.com")
"""

from ast import List
from dataclasses import field
import re
import os
import mysql.connector
import logging
from typing import List

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class that
    redacts sensitive data in log messages."""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record and redact sensitive data.

        Args:
            record (logging.LogRecord): LogRecord
            instance containing the log message.

        Returns:
            str: The formatted log message with sensitive data redacted.
        """
        message = super(RedactingFormatter, self).format(record)
        redacted = filter_datum(self.fields, self.REDACTION,
                                message, self.SEPARATOR)
        return redacted


def get_logger() -> logging.Logger:
    """
    Return a logging.Logger object configured with the RedactingFormatter.

    Returns:
        logging.Logger: The configured logger object.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()

    formatter = RedactingFormatter(PII_FIELDS)

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def filter_datum(fields: List[str],
                 redaction: str, message: str, separator: str) -> str:
    """Filter sensitive data in a message.

    Args:
        fields (List[str]): The list of sensitive fields to be redacted.
        redaction (str): The redaction string to replace sensitive data.
        message (str): The message containing sensitive data.
        separator (str): The separator used to
        separate key-value pairs in the message.

    Returns:
        str: The filtered message with the sensitive data redacted.
    """
    for field in fields:
        message = re.sub(field+'=.*?'+separator,
                         field+'='+redaction+separator, message)
    return message


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    return db connection
    """
    user = os.getenv('PERSONAL_DATA_DB_USERNAME') or "root"
    passwd = os.getenv('PERSONAL_DATA_DB_PASSWORD') or ""
    host = os.getenv('PERSONAL_DATA_DB_HOST') or "localhost"
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')
    conn = mysql.connector.connect(user=user,
                                   password=passwd,
                                   host=host,
                                   database=db_name)
    return conn


def main():
    """
    main entry point
    """
    db = get_db()
    logger = get_logger()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    fields = cursor.column_names
    for row in cursor:
        message = "".join("{}={}; ".format(k, v) for k, v in zip(fields, row))
        logger.info(message.strip())
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
