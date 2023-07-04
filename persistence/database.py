
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from definitions import ROOT_DIR
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import declarative_base
import os
from sqlalchemy import exc

Base = declarative_base()
engine = create_async_engine(
    "sqlite+aiosqlite:///"+os.path.join(ROOT_DIR, 'observer.db'),
    echo=False
)

MAX_TRIES = 2

async def initialize():
    async with engine.begin() as conn:
        # await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


async def db_session():
    return sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def add(instance):
    number_of_tried = 0
    async_session = await db_session()
    while number_of_tried < MAX_TRIES:
        try:
            async with async_session() as session:
                async with session.begin():
                    session.add(instance)
                    await session.commit()
            error = False
        except exc.SQLAlchemyError as e:
            if number_of_tried == MAX_TRIES:
                raise e
            error = True
        if not error:
            break
        number_of_tried = number_of_tried + 1
        await asyncio.sleep(number_of_tried*1)

