from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, status, BackgroundTasks
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from sqlmodel.ext.asyncio.session import AsyncSession

from src.redis import add_jti_to_blocklist
from src.config import Config
from src.database import get_session

from auth.dependencies import (
    AccessTokenBearer,
    RefreshTokenBearer,
    RoleChecker,
    get_current_user,
)
from auth.schemas import (
    UserCreateModel,
    UserLoginModel,
    UserModel
)
from auth.service import UserService
from auth.utils import (
    create_access_token,
    verify_password,
    generate_passwd_hash
)
from src.exceptions import (
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    InvalidToken
)

auth_router = APIRouter()
user_service = UserService()
role_checker = RoleChecker(["admin", "user"])

REFRESH_TOKEN_EXPIRY = Config.JWT_EXPIRY


@auth_router.post(
    "/signup", 
    status_code=status.HTTP_201_CREATED
)
async def create_user_view(
    user_data: UserCreateModel,
    session: AsyncSession = Depends(get_session),
):
    email = user_data.email
    user_exists = await user_service.user_exists(
        email, session
    )

    if user_exists:
        raise UserAlreadyExists()

    new_user = await user_service.create_user(
        user_data, session
    )

    return {
        "message": f"Account Created! \
            Check email to verify your account",
        "user": new_user,
    }


@auth_router.post("/login")
async def login_user_view(
    login_data: UserLoginModel,
    session: AsyncSession = Depends(get_session)
):
    email = login_data.email
    password = login_data.password

    user = await user_service.get_user_by_email(
        email, session
    )

    if user is not None:
        password_valid = verify_password(
            password, user.password_hash
        )

        if password_valid:
            access_token = create_access_token(
                user_data={
                    "email": user.email,
                    "user_uid": str(user.uid),
                    "role": user.role,
                }
            )

            refresh_token = create_access_token(
                user_data={
                    "email": user.email,
                    "user_uid": str(user.uid)
                },
                refresh=True,
                expiry=timedelta(days=REFRESH_TOKEN_EXPIRY),
            )

            return JSONResponse(
                content={
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "email": user.email,
                        "uid": str(user.uid)
                    },
                }
            )

    raise InvalidCredentials()


@auth_router.get("/refresh_token")
async def get_new_access_token_view(
    token_details: dict = Depends(
        RefreshTokenBearer()
    )
):
    expiry_timestamp = token_details["exp"]

    if (
        datetime.fromtimestamp(expiry_timestamp) 
        > datetime.now()
    ):
        new_access_token = create_access_token(
            user_data=token_details["user"]
        )

        return JSONResponse(
            content={
                "access_token": new_access_token
            }
        )

    raise InvalidToken


@auth_router.get("/me", response_model=UserModel)
async def get_current_user(
    user=Depends(get_current_user), _: bool = Depends(role_checker)
):
    return user


@auth_router.get("/logout")
async def logout_view(
    token_details: dict = Depends(AccessTokenBearer())
):
    jti = token_details["jti"]

    await add_jti_to_blocklist(jti)

    return JSONResponse(
        content={
            "message": "Logged Out Successfully"
        },
        status_code=status.HTTP_200_OK
    )
