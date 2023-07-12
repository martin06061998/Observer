
from sqlalchemy import JSON, Column, ForeignKey, Integer, String, func,DateTime
from utilities.util import md5
from persistence.database import Base
#import logging

class Parameter(Base):
    """A taint trace represents a trace of a taint to a specific vulnerability."""
    __tablename__ = 'parameters'
    id = Column(String(50), primary_key=True)
    name = Column(String(50), nullable=False)
    data_type = Column(String(50),  nullable=False)
    http_method = Column(String(50),  nullable=False)
    example_values = Column(JSON)
    part = Column(String(50),  nullable=False)
    original_url = Column(String,nullable=False)
    endpoint = Column(String,  nullable=False)
    group = Column(String(50))
    body_data_type = Column(String(50))


    @classmethod
    def calculate_id(cls, name: str|bytes, part:str, http_method: str, original_url:str , endpoint: str):
        if name is None:
            raise ValueError(f"Can not calculate parameter id due to name is None")
        if http_method is None:
            raise ValueError(f"Can not calculate parameter id due to http_method is None")
        if endpoint is None:
            raise ValueError(f"Can not calculate parameter id due to endpoint is None")
        if original_url is None:
            raise ValueError(f"Can not calculate parameter id due to original_url is None")
        if part is None:
            raise ValueError(f"Can not calculate parameter id due to part is None")
        ret =  md5(name+http_method.lower()+part.lower()+endpoint.split("?")[0])
        return ret

    def __init__(self, name: str, http_method: str, example_values: list[str|bytes], part: str,endpoint:str,original_url:str,group_id:str=None, data_type: str = "string",body_data_type:str="Unknown"):
        if type(name) is bytes:
            name = name.decode()
        self.id = Parameter.calculate_id(name=name,part=part,http_method=http_method,original_url=original_url,endpoint=endpoint)
        self.name = name
        self.http_method = http_method.lower()
        self.endpoint = endpoint
        self.data_type = data_type
        self.original_url = original_url
        self.body_data_type = body_data_type
        self.example_values = []
        for v in example_values:
            if type(v) is bytes:
                self.example_values.append(v.decode())
            else:
                self.example_values.append(v)
        self.part = part
        self.group = group_id

    def json(self):
        return {
            "id":self.id,
            "name":self.name,
            "data_type": self.data_type,
            "http_method":self.http_method,
            "example_values":self.example_values,
            "part":self.part,
            "original_url":self.original_url,
            "endpoint":self.endpoint,
            "group":self.group,
            "enctype":self.body_data_type
        }

class ParamFlowMap(Base):
    __tablename__ = "paramflows"
    group_id = Column(String(50), primary_key=True)
    flow_id = Column(String(50), primary_key=True)
    created_date = Column(DateTime(timezone=True), server_default=func.now())
    
    def __init__(self,group_id,flow_id):
        self.group_id = group_id
        self.flow_id = flow_id
