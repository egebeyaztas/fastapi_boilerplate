import uuid
from typing import Any

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from auth.utils import generate_password_hash, verify_password
from auth.models import User, UserCreate, UserUpdate


async def create_user(
    *, session: AsyncSession,
    user_create: UserCreate
) -> User:
    db_obj = User.model_validate(
        user_create,
        update={
            "hashed_password": generate_password_hash(
                user_create.password
            )
        }
    )
    session.add(db_obj)
    await session.commit()
    await session.refresh(db_obj)
    return db_obj


async def update_user(
    *, session: AsyncSession,
    db_user: User,
    user_in: UserUpdate
) -> Any:
    user_data = user_in.model_dump(exclude_unset=True)
    extra_data = {}
    if "password" in user_data:
        password = user_data["password"]
        hashed_password = generate_password_hash(
            password
        )
        extra_data["hashed_password"] = hashed_password
    db_user.sqlmodel_update(
        user_data,
        update=extra_data
    )
    session.add(db_user)
    await session.commit()
    await session.refresh(db_user)
    return db_user
