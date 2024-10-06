from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel
from contextlib import asynccontextmanager

from src.database import engine, get_session

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Server is starting...")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    yield

    print("Server is shutting down...")

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root(session: AsyncSession = Depends(get_session)):
    return {"message": "Hello World"}