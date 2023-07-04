
import random
import time
from sqlalchemy import Column, Float, Integer, String, LargeBinary, Boolean, JSON
from persistence.database import Base
from mitmproxy import http
from utilities.util import md5

class ObHttpFlow(Base):
    __tablename__ = 'flows'
    id = Column(String(50), primary_key=True)
    request_host = Column(String(125), nullable=False)
    request_scheme = Column(String(50), nullable=False)
    request_path = Column(String, nullable=False)
    http_method = Column(String(50), nullable=False)
    url = Column(String, nullable=False)
    request_body_content = Column(LargeBinary)
    response_body_content = Column(LargeBinary)
    response_body_size = Column(Integer)
    request_body_size = Column(Integer)
    status_code = Column(Integer, nullable=False)
    is_clone = Column(Boolean, nullable=False)
    timestamp = Column(Float, nullable=False)
    _request_headers = Column(JSON, nullable=False)
    _response_headers = Column(JSON, nullable=False)
    request_body_type = Column(String(125))
    _request_body_parameters = Column(JSON)
    _query = Column(JSON)

    def __init__(self, flow: http.HTTPFlow = None, request_scheme: str = None, request_host: str = None, request_path: str = None, http_method: str = None, url: str = None, status_code: int = None, timestamp: float = None, request_headers: dict[str:str] = None, response_headers: dict[str:str] = None, response_body_content: bytes = None, request_body_parameters: dict[str:str] = None, query: dict[str:str] = None):
        self._flow = flow
        if flow:
            # General Info
            self.id = md5(flow.id)
            flow.request.headers["flow-id"] = self.id
            self.is_clone = flow.is_replay == "request"

            # Parsing Request
            self.request_body_content = flow.request.content
            if self.request_body_content:
                self.request_body_size = len(flow.request.content)
            else:
                self.request_body_size = None


            if flow.request.multipart_form:
                self.request_body_parameters = flow.request.multipart_form
                self.request_body_type = "multipart/form-data"
            elif flow.request.urlencoded_form:
                self.request_body_parameters = flow.request.urlencoded_form
                self.request_body_type = "application/x-www-form-urlencoded"
            elif flow.request.raw_content and "content-type" in flow.request.headers and flow.request.headers["content-type"] == "application/json":
                try:
                    self.request_body_parameters = flow.request.json()
                except:
                    self.request_body_parameters = None
                self.request_body_type = "application/json"

            else:
                self.request_body_parameters = None
                self.request_body_type = None
            
            #self._request_body_parameters = None
                
   

            self.query = flow.request.query
            if self.query:
                self._query = dict()
                for key, value in self.query.items():
                    self._query[key] = value
              

            self.url = flow.request.pretty_url
            self.request_host = flow.request.host
            self.http_method = flow.request.method
            self.request_scheme = flow.request.scheme
            self.request_path = flow.request.path.split("?")[0]
            self.request_headers = flow.request.headers
            # self.request_headers['request-id'] = self.id
            self._request_headers = dict()
            for key, value in self.request_headers.items():
                self._request_headers[key] = value
            # End

            # Start Parsing Response
            if flow.response:
                self.response_body_content = flow.response.content
                if self.response_body_content:
                    self.response_body_size = len(flow.response.content)
                else:
                    self.response_body_size = None
                self.timestamp = flow.response.timestamp_end - flow.request.timestamp_start
                self.response_headers = flow.response.headers
                self._response_headers = dict()
                for key, value in self.response_headers.items():
                    self._response_headers[key] = value
                self.status_code = flow.response.status_code
            else:
                self.response_body_content = None
                self.response_body_size = None
                self.timestamp = None
                self.response_headers = None
                self.status_code = None
            # END
        else:
            self.request_scheme = request_scheme
            self.request_host = request_host
            self.request_path = request_path
            self.http_method = http_method
            self.url = url
            # assign id
            self.id = md5(f"{time.time()}{self.url}{random.randrange(10000)}")
            self.timestamp = timestamp
            self.status_code = status_code
            self._request_headers = request_headers
            self._response_headers = response_headers
            self.response_body_content = response_body_content
            self.request_body_parameters = request_body_parameters
            if self.response_body_content:
                self.response_body_size = len(self.response_body_content)
            self.query = query
            self._query = query
    
        if self.request_body_parameters:
            self._request_body_parameters = dict()
            for key, value in self.request_body_parameters.items():
                if "multipart/form-data" in self.request_body_type:
                    self._request_body_parameters[key.decode(errors="ignore")] = value.decode(errors="ignore")
                else:
                    self._request_body_parameters[key] = value
        

    def copy(self):
        clone = self._flow.copy()
        ret = ObHttpFlow(flow=clone)
        return ret


    def in_trace(self):
        return "tag" in self.request_headers

    def is_replayed(self):
        return self.is_clone
    
    def has_no_parameters(self):
        return self.request_body_parameters is None and self.query is None
    
    def empty_request_body(self):
        return self.request_body_content == None
    
    def get_parameter_value(self,param:str|bytes):
        if param is bytes:
            param = param.decode()
        if param in self.query:
            return self.query[param]
        if param in self.request_body_parameters:
            return self.request_body_parameters[param]
    
    def get_all_parameter_names(self):
        ret = []
        if self.request_body_parameters:
            for name in self.request_body_parameters:
                if name is bytes:
                    name = name.decode()
                ret.append(name)
        if self.query:
            for name in self.query:
                ret.append(name)
        return ret
