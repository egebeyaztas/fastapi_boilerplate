import jwt
import logging
from typing import Any
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone

from src.config import settings
from src.utils import EmailData, render_email_template

passwd_context = CryptContext(schemes=["bcrypt"])

ACCESS_TOKEN_EXPIRY = settings.JWT_EXPIRY
REFRESH_TOKEN_EXPIRY = settings.JWT_EXPIRY

JWT_ALGORITHM = "HS256"


def generate_password_hash(password: str) -> str:
    hash = passwd_context.hash(password)

    return hash


def verify_password(password: str, hash: str) -> bool:
    return passwd_context.verify(password, hash)


def create_access_token(
    subject: str | Any,
    expiry: timedelta = None
):
    payload = {}
    payload["sub"] = subject
    payload["exp"] = datetime.now() + (
        expiry
        if expiry is not None
        else timedelta(seconds=ACCESS_TOKEN_EXPIRY)
    )

    token = jwt.encode(
        payload=payload,
        key=settings.SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )

    return token


def decode_token(token: str) -> dict:
    try:
        token_data = jwt.decode(
            jwt=token,
            key=settings.SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )

        return token_data

    except jwt.PyJWTError as e:
        logging.exception(e)
        return None


async def generate_reset_password_email(
    email_to: str,
    email: str,
    token: str
) -> EmailData:
    project_name = settings.PROJECT_NAME
    subject = f"{project_name} - Password \
        recovery for user {email}"
    link = f"{settings.FRONTEND_HOST}/\
        reset-password?token={token}"
    html_content = await render_email_template(
        template_name="reset_password.html",
        context={
            "project_name": settings.PROJECT_NAME,
            "username": email,
            "email": email_to,
            "valid_hours": settings.EMAIL_RESET_TOKEN_EXPIRE_HOURS,
            "link": link,
        },
    )
    return EmailData(
        html_content=html_content,
        subject=subject
    )


def generate_new_account_email(
    email_to: str, username: str, password: str
) -> EmailData:
    project_name = settings.PROJECT_NAME
    subject = f"{project_name} - New \
        account for user {username}"
    html_content = render_email_template(
        template_name="new_account.html",
        context={
            "project_name": settings.PROJECT_NAME,
            "username": username,
            "password": password,
            "email": email_to,
            "link": settings.FRONTEND_HOST,
        },
    )
    return EmailData(
        html_content=html_content,
        subject=subject
    )


def generate_password_reset_token(email: str) -> str:
    delta = timedelta(
        hours=settings.EMAIL_RESET_TOKEN_EXPIRE_HOURS
    )
    now = datetime.now(timezone.utc)
    expires = now + delta
    exp = expires.timestamp()
    encoded_jwt = jwt.encode(
        {"exp": exp, "nbf": now, "sub": email},
        settings.SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )
    return encoded_jwt


def verify_password_reset_token(
        token: str
) -> str | None:
    try:
        decoded_token = decode_token(token)
        return str(decoded_token["sub"])
    except jwt.InvalidTokenError:
        return None
