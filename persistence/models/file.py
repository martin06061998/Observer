import hashlib
from sqlalchemy import Column, PickleType, Float, String
from persistence.database import Base



class PickleFile(Base):
    __tablename__ = 'files'
    id = Column(String(50), primary_key=True)
    path = Column(String(125), unique=True, nullable=False,index=True)
    data = Column(PickleType, nullable=False)
    last_modified = Column(Float, nullable=False)

    def __init__(self, path: str, data, last_modified: float):
        self.id = hashlib.md5(path.encode()).hexdigest()
        self.data = data
        self.path = path
        self.last_modified = last_modified
