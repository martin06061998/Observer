
import asyncio
from asyncio.log import logger
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from definitions import ROOT_DIR
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import declarative_base
import os
from sqlalchemy import exc
from sqlalchemy.dialects.sqlite import insert as sqlite_upsert
from sqlalchemy.orm.session import Session

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


async def add_or_do_nothing(instance):
    number_of_tried = 0
    async_session = await db_session()
    success = False
    while number_of_tried < MAX_TRIES and success != True:
        session:Session
        async with async_session() as session:
            try:
                async with session.begin():
                    klass = type(instance)
                    column_names = klass.__table__.columns.keys()
                    data = {k: v for k, v in vars(instance).items() if k in column_names}
                    stmt = sqlite_upsert(klass).values(**data)
                    stmt = stmt.on_conflict_do_nothing(index_elements=klass.__table__.primary_key)
                    await session.execute(stmt)
                    await session.commit()
                success = True
            except exc.IntegrityError as i:
                logger.warning(f"IntegrityError of type {klass}: {str(i)}")
                break
            except exc.OperationalError as o:
                logger.warning(f"Database error {str(o)}")
            finally:
                number_of_tried = number_of_tried + 1
                if not success:
                    await asyncio.sleep(2)


async def add_or_update(instance,update_tale_names:list[str]):
    number_of_tried = 0
    async_session = await db_session()
    success = False
    while number_of_tried < MAX_TRIES and success != True:
        session:Session
        async with async_session() as session:
            #logger.warning(type(session))
            try:
                async with session.begin():
                    klass = type(instance)
                    column_names = klass.__table__.columns.keys()
                    data = {k: v for k, v in vars(instance).items() if k in column_names}
                    update_data = {k:v for k,v in data.items() if k in update_tale_names}
                    stmt = sqlite_upsert(klass).values(**data)
                    stmt = stmt.on_conflict_do_update(index_elements=klass.__table__.primary_key,set_=update_data)
                    await session.execute(stmt)
                    await session.commit()
                success = True
            except exc.IntegrityError as i:
                logger.warning(f"IntegrityError of type {klass}: {str(i)}")
                break
            except exc.OperationalError as o:
                logger.warning(f"Database error {str(o)}")
            finally:
                number_of_tried = number_of_tried + 1
                if not success:
                    await asyncio.sleep(2)


            

