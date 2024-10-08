from sqlmodel import SQLModel
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from contextlib import asynccontextmanager
from src.database import engine, get_session
from src.exceptions import register_all_errors
from auth.routers.login import router as auth_router
from auth.routers.users import router as user_router

version = "v1"

version_prefix =f"/api/{version}"

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Server is starting...")
    async with engine.begin() as conn:
        await conn.run_sync(
            SQLModel.metadata.create_all
        )

    yield

    print("Server is shutting down...")

app = FastAPI(lifespan=lifespan)
app.include_router(
    auth_router,
    tags=["login"]
)
app.include_router(
    user_router,
    prefix=f"{version_prefix}/users",
    tags=["users"]
)

register_all_errors(app)

@app.get("/")
async def root(
    session: AsyncSession = Depends(get_session)
):
    return {"message": "Hello World"}