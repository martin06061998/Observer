
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from definitions import ROOT_DIR
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import declarative_base
import os


Base = declarative_base()
engine = create_async_engine(
    "sqlite+aiosqlite:///"+os.path.join(ROOT_DIR, 'observer.db'),
    echo=False
)


async def initialize():
    async with engine.begin() as conn:
        # await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


async def add(instance):
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        async with session.begin():
            session.add(instance)
        await session.commit()


async def db_session():
    return sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
