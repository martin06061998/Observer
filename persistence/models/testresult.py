from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from persistence.database import Base
#import logging

class TestResult(Base):
    __tablename__ = 'testresults'
    id = Column(Integer, primary_key=True, autoincrement="auto")
    parameter_id = Column(String(50),ForeignKey('flows.id'),nullable=False)
    bug_type = Column(String(50),nullable=False)
    template_path = Column(String(50),nullable=False)
    is_vulnerable = Column(Boolean)
    
    def __init__(self,parameter_id:str,bug_type:str,template_path:str,is_vulnerable:bool):
        self.parameter_id = parameter_id
        self.bug_type = bug_type
        self.template_path = template_path
        self.is_vulnerable = is_vulnerable