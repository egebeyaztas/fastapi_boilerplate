from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel
from contextlib import asynccontextmanager
from src.auth.routers import auth_router
from src.database import engine, get_session
from src.exceptions import register_all_errors

version = "v1"

version_prefix =f"/api/{version}"

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Server is starting...")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    yield

    print("Server is shutting down...")

app = FastAPI(lifespan=lifespan)
app.include_router(auth_router, prefix=f"{version_prefix}/auth", tags=["auth"])

register_all_errors(app)

@app.get("/")
async def root(session: AsyncSession = Depends(get_session)):
    return {"message": "Hello World"}