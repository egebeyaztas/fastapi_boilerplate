import uuid
from typing import Any
from sqlmodel import select, delete, func
from fastapi import APIRouter, Depends, HTTPException, status
from src.exceptions import UserAlreadyExists
from auth import crud
from auth.utils import generate_password_hash, verify_password
from auth.dependencies import (
    SessionDep,
    CurrentUser,
    get_current_active_superuser
)
from auth.models import (
    Message,
    User,
    UserCreate,
    UserRegister,
    UserUpdate,
    UserUpdateMe,
    UserPublic,
    UsersPublic,
    UpdatePassword,
)
from auth.service import UserService


router = APIRouter()
user_service = UserService()


@router.post(
    "/create_user",
    dependencies=[
        Depends(get_current_active_superuser)
    ],
    response_model=UserPublic
)
async def create_user(
    *, session: SessionDep,
    user_in: UserCreate
) -> Any:
    """
    Create new user.
    """
    user = await user_service.get_user_by_email(
        session=session, 
        email=user_in.email
    )
    if user:
        raise UserAlreadyExists()

    user = await crud.create_user(
        session=session,
        user_create=user_in
    )
    """
    if settings.emails_enabled and user_in.email:
        email_data = generate_new_account_email(
            email_to=user_in.email,
            username=user_in.email,
            password=user_in.password
        )
        send_email(
            email_to=user_in.email,
            subject=email_data.subject,
            html_content=email_data.html_content,
        )
    """
    return user


@router.post(
    "/register", 
    status_code=status.HTTP_201_CREATED,
    response_model=UserPublic
)
async def register_user(
    user_data: UserRegister,
    session: SessionDep,
) -> Any:
    email = user_data.email
    user = await user_service.get_user_by_email(
        email, session
    )
    if user:
        raise UserAlreadyExists()

    user = await crud.create_user(
        user_data, session
    )

    return {
        "message": f"Account Created! \
            Check email to verify your account",
        "user": user,
    }


@router.get(
    "/",
    dependencies=[
        Depends(get_current_active_superuser)
    ],
    response_model=UsersPublic
)
async def get_users(
    session: SessionDep,
    offset: int = 0,
    limit: int = 100
) -> Any:

    count_statement = select(func.count()).select_from(
        User
    )
    count = await session.exec(count_statement).one()

    statement = select(User).offset(offset).limit(limit)
    users = await session.exec(statement).all()
    return UsersPublic(
        data=users,
        count=count
    )


@router.patch("/profile", response_model=UserPublic)
async def update_user_me(
    *, session: SessionDep,
    user_in: UserUpdateMe,
    current_user: CurrentUser
) -> Any:
    """
    Update own user.
    """
    if user_in.email:
        existing_user = await crud.get_user_by_email(
            session=session,
            email=user_in.email
        )
        if (
            existing_user 
            and (existing_user.id != current_user.id)
        ):
            raise HTTPException(
                status_code=409,
                detail="User with this email already exists"
            )
    user_data = user_in.model_dump(exclude_unset=True)
    current_user.sqlmodel_update(user_data)
    session.add(current_user)
    await session.commit()
    await session.refresh(current_user)
    return current_user


@router.patch(
    "/profile/password",
    response_model=Message
)
async def update_password_me(
    *, session: SessionDep,
    body: UpdatePassword,
    current_user: CurrentUser
) -> Any:
    """
    Update own password.
    """
    if not verify_password(
        body.current_password,
        current_user.hashed_password
    ):
        raise HTTPException(
            status_code=400,
            detail="Incorrect password"
        )
    if body.current_password == body.new_password:
        raise HTTPException(
            status_code=400, 
            detail="New password cannot be \
                the same as the current one"
        )
    hashed_password = generate_password_hash(
        body.new_password
    )
    current_user.hashed_password = hashed_password
    session.add(current_user)
    await session.commit()
    return Message(
        message="Password updated successfully"
    )


@router.delete(
    "/profile",
    response_model=Message
)
async def delete_user_me(
    session: SessionDep,
    current_user: CurrentUser
) -> Any:
    """
    Delete own user.
    """
    if current_user.is_superuser:
        raise HTTPException(
            status_code=403, 
            detail="Super users are not \
                allowed to delete themselves"
        )
    await session.delete(current_user)
    await session.commit()
    return Message(
        message="User deleted successfully"
    )


@router.get("/profile", response_model=User)
async def get_current_user(
    user: User = Depends(CurrentUser)
):
    return user


@router.get(
    "/{user_id}",
    response_model=UserPublic
)
def read_user_by_id(
    user_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser
) -> Any:
    """
    Get a specific user by id.
    """
    user = session.get(User, user_id)
    if user == current_user:
        return user
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="The user doesn't have enough privileges",
        )
    return user


@router.patch(
    "/{user_id}",
    dependencies=[
        Depends(get_current_active_superuser)
    ],
    response_model=UserPublic,
)
async def update_user(
    *,
    session: SessionDep,
    user_id: uuid.UUID,
    user_in: UserUpdate,
) -> Any:
    """
    Update a user.
    """
    db_user = await session.get(User, user_id)
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="The user with this id \
                does not exist in the system",
        )
    if user_in.email:
        existing_user = await user_service.get_user_by_email(
            session=session, 
            email=user_in.email
        )
        if existing_user and existing_user.id != user_id:
            raise HTTPException(
                status_code=409,
                detail="User with this email already exists"
            )

    db_user = await crud.update_user(
        session=session,
        db_user=db_user,
        user_in=user_in
    )
    return db_user


@router.delete(
    "/{user_id}",
    dependencies=[
        Depends(get_current_active_superuser)
    ]
)
async def delete_user(
    user_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser
) -> Any:
    """
    Delete a user by id.
    """
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    if user == current_user:
        raise HTTPException(
            status_code=403,
            detail="Super users are not \
                allowed to delete themselves"
        )
    await session.delete(user)
    await session.commit()
    return Message(
        message="User deleted successfully"
    )