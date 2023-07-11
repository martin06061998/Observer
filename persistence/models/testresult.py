from sqlalchemy import JSON, Boolean, Column, String
from persistence.database import Base
#import logging

class TestResult(Base):
    __tablename__ = 'testresults'
    vector_id = Column(String(50), primary_key=True)
    parameter_id = Column(String(50),primary_key=True)
    bug_type = Column(String(50),nullable=False)
    template_path = Column(String(50),nullable=False)
    payloads = Column(JSON)
    is_vulnerable = Column(Boolean)
    
    def __init__(self,parameter_id:str,vector_id:str,bug_type:str,template_path:str,is_vulnerable:bool,payloads:list[str]=None):
        self.parameter_id = parameter_id
        self.vector_id = vector_id
        self.bug_type = bug_type
        self.template_path = template_path
        self.is_vulnerable = is_vulnerable
        self.payloads = payloads