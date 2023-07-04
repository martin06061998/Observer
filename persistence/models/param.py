from sqlalchemy import JSON, Column, ForeignKey, Integer, String
from utilities.util import md5,is_absolute_url,is_relative_url
from persistence.database import Base
from persistence.models.flow import ObHttpFlow
import logging

class Parameter(Base):
    """A taint trace represents a trace of a taint to a specific vulnerability."""
    __tablename__ = 'parameters'
    id = Column(String(50), primary_key=True)
    name = Column(String(50), nullable=False)
    data_type = Column(String(50),  nullable=False)
    scheme = Column(String(50),  nullable=False)
    host = Column(String(50),  nullable=False)
    #path = Column(String(50),  nullable=False)
    http_method = Column(String(50),  nullable=False)
    example_values = Column(JSON)
    total_of_trace = Column(Integer, default=1)
    part = Column(String(50),  nullable=False)
    original_url = Column(String)
    endpoint = Column(String,  nullable=False)
    request_template_id = Column(String(50),  nullable=False)





    @classmethod
    def calculate_id(cls, name: str|bytes, http_method: str, scheme: str, host: str, endpoint: str):
        return md5(name+http_method+scheme+host+endpoint)

    def __init__(self, name: str|bytes, http_method: str, scheme: str, host: str, data_type: str, example_values: list[str|bytes], part: str,request_template_id:str,endpoint:str,original_url:str):
        if type(name) is bytes:
            name = name.decode()
        self.name = name
        self.http_method = http_method.lower()
        self.scheme = scheme
        self.host = host
    
        self.endpoint = endpoint
        self.data_type = data_type
        self.id = Parameter.calculate_id(name, http_method, scheme, host, endpoint)
        self.original_url = original_url
        self.example_values = []
        for v in example_values:
            if type(v) is bytes:
                self.example_values.append(v.decode())
            else:
                self.example_values.append(v)
        self.part = part
        self.request_template_id = request_template_id

    @classmethod
    def new_parameter(cls, param: str, flow: ObHttpFlow,endpoint:str=None,data_type="string",original_url=None):
        part = None
        if flow.request_body_type == "multipart/form-data":
            param = param.encode()
        if param in flow.query:
            part = "query"
        elif param in flow.request_body_parameters:
            part = "body"
        
        example_values = [flow.all_parameters[param]]
        if original_url is None:
            original_url = flow.url
        
        if endpoint is None:
            endpoint = flow.url

        new_input = Parameter(name=param, http_method=flow.http_method, scheme=flow.request_scheme,host=flow.request_host, data_type=data_type, example_values=example_values, part=part,request_template_id=flow.id,endpoint=endpoint,original_url=original_url)
        return new_input

class ParamFlowMap(Base):
    __tablename__ = "paramflows"
    id = Column(Integer, primary_key=True, autoincrement="auto")
    parameter_id = Column(String(50), ForeignKey(
        'parameters.id'), nullable=False,)
    flow_id = Column(String(50), ForeignKey('flows.id'), nullable=False)
