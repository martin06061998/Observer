from sqlalchemy import JSON, Column, ForeignKey, Integer, String
from utilities.util import md5
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
    path = Column(String(50),  nullable=False)
    http_method = Column(String(50),  nullable=False)
    example_values = Column(JSON)
    total_of_trace = Column(Integer, default=1)
    part = Column(String(50),  nullable=False)

    @classmethod
    def calculate_id(cls, name: str, http_method: str, scheme: str, host: str, path: str):
        path = path.split("?")[0]
        return md5(name+http_method+scheme+host+path)

    def __init__(self, name: str, http_method: str, scheme: str, host: str, path: str, data_type: str, example_values: list[str], part: str):
        self.name = name
        self.http_method = http_method
        self.scheme = scheme
        self.host = host
        path = path.split("?")[0]
        self.path = path
        self.data_type = data_type
        self.id = Parameter.calculate_id(name, http_method, scheme, host, path)
        self.example_values = example_values
        self.part = part

    @classmethod
    def new_parameter(cls, param: str, flow: ObHttpFlow):
        data_type = "number"

        part = None
        if param in flow.query:
            part = "query"
        elif param in flow.request_body_parameters:
            part = "body"
        example_values = [flow.all_parameters[param]]
        for value in example_values:
            if not str(value).isdigit():
                data_type = "string"
                break
        new_input = Parameter(name=param, http_method=flow.http_method, scheme=flow.request_scheme,
                              host=flow.request_host, path=flow.request_path, data_type=data_type, example_values=example_values, part=part)
        return new_input


class ParamFlowMap(Base):
    __tablename__ = "paramflows"
    id = Column(Integer, primary_key=True, autoincrement="auto")
    parameter_id = Column(String(50), ForeignKey(
        'parameters.id'), nullable=False,)
    flow_id = Column(String(50), ForeignKey('flows.id'), nullable=False)
