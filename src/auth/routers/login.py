from datetime import timedelta
from typing import Annotated, Any
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, JSONResponse
from src.config import settings
from src.utils import send_email
from src.exceptions import (
    InvalidCredentials
)
from auth import crud
from auth.dependencies import (
    SessionDep,
    get_current_active_superuser
)
from auth.models import (
    Message,
    NewPassword,
    User
)
from auth.service import UserService
from auth.utils import (
    ACCESS_TOKEN_EXPIRY,
    create_access_token,
    generate_password_hash,
    generate_password_reset_token,
    generate_reset_password_email,
    verify_password,
    verify_password_reset_token
)

router = APIRouter()
user_service = UserService()

REFRESH_TOKEN_EXPIRY = settings.JWT_EXPIRY


@router.post("/login")
async def login_user(
    session: SessionDep,
    form_data: Annotated[
        OAuth2PasswordRequestForm,
        Depends()
    ]
):
    email = form_data.email
    password = form_data.password

    user = await user_service.get_user_by_email(
        email, session
    )

    if user is not None:
        password_valid = verify_password(
            password, user.password_hash
        )

        if password_valid:
            access_token = create_access_token(
                subject=str(user.id),
                expiry=timedelta(
                    minutes=ACCESS_TOKEN_EXPIRY
                ),
            )
            return JSONResponse(
                content={
                    "message": "Login successful",
                    "access_token": access_token,
                    "user": {
                        "email": user.email,
                        "id": str(user.id)
                    },
                }
            )

    raise InvalidCredentials()


@router.post("/password-recovery/{email}")
async def recover_password(
    email: str, 
    session: SessionDep
) -> Message:
    """
    Password Recovery
    """
    user = await crud.get_user_by_email(
        session=session,
        email=email
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this email \
                does not exist in the system.",
        )
    password_reset_token = generate_password_reset_token(
        email=email
    )
    email_data = await generate_reset_password_email(
        email_to=user.email,
        email=email,
        token=password_reset_token
    )
    send_email(
        email_to=user.email,
        subject=email_data.subject,
        html_content=email_data.html_content,
    )
    return Message(
        message="Password recovery email sent"
    )


@router.post("/reset-password/")
async def reset_password(
    session: SessionDep,
    body: NewPassword
) -> Message:
    """
    Reset password
    """
    email = verify_password_reset_token(
        token=body.token
    )
    if not email:
        raise HTTPException(
            status_code=400,
            detail="Invalid token"
        )
    user = await user_service.get_user_by_email(
        email=email,
        session=session
    )
    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this email \
                does not exist in the system.",
        )
    elif not user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Inactive user"
        )
    hashed_password = generate_password_hash(
        password=body.new_password
    )
    user.hashed_password = hashed_password
    session.add(user)
    await session.commit()
    return Message(
        message="Password updated successfully"
    )


@router.post(
    "/password-recovery-html-content/{email}",
    dependencies=[
        Depends(get_current_active_superuser)
    ],
    response_class=HTMLResponse,
)
async def recover_password_html_content(
    email: str, session: SessionDep
) -> Any:
    """
    HTML Content for Password Recovery
    """
    user = await user_service.get_user_by_email(
        email=email,
        session=session
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this username \
                does not exist in the system.",
        )
    password_reset_token = generate_password_reset_token(
        email=email
    )
    email_data = await generate_reset_password_email(
        email_to=user.email,
        email=email,
        token=password_reset_token
    )

    return HTMLResponse(
        content=email_data.html_content,
        headers={"subject:": email_data.subject}
    )
