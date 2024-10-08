from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from auth.models import User
from auth.utils import verify_password


class UserService:
    async def get_user_by_email(
        self, email: str, 
        session: AsyncSession
    ):
        statement = select(User).where(User.email == email)
        result = await session.exec(statement)
        user = result.first()

        return user
    
    async def authenticate(
        self, *,
        session: AsyncSession,
        email: str,
        password: str
    ) -> User | None:
        db_user = await self.get_user_by_email(
            session=session,
            email=email
        )
        if not db_user:
            return None
        if not verify_password(
            password,
            db_user.hashed_password
        ):
            return None
        return db_user
