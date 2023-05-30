
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()


class Database:
    engine = None

    def initialize():
        Database.engine = create_engine('sqlite://', pool_size=20, echo=False)
        Base.metadata.create_all(Database.engine)

    def get_session():
        if Database.engine is None:
            Database.initialize()
        return sessionmaker(bind=Database.engine)()

    def clean():
        Database.engine.dispose()
