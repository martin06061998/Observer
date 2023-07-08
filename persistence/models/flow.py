
import time
from venv import logger
import requests
from sqlalchemy import Column, Float, Integer, String, LargeBinary, Boolean, JSON
from persistence.database import Base
from mitmproxy import http
from utilities.util import md5
from urllib.parse import urlparse

class ObHttpFlow(Base):
    """A Proxy To Class http.HTTPFlow

    Args:
        Base (_type_): _description_

    Returns:
        _type_: _description_
    """
    __tablename__ = 'flows'
    id = Column(String(50), primary_key=True)
    host = Column(String(125), nullable=False)
    port = Column(Integer, nullable=False)
    http_method = Column(String(50), nullable=False)
    url = Column(String, nullable=False)
    request_body_content = Column(LargeBinary)
    response_body_content = Column(LargeBinary)
    response_body_size = Column(Integer)
    request_body_size = Column(Integer)
    body_data_type = Column(String(50))
    query = Column(JSON)
    body_parameters = Column(JSON)
    request_headers = Column(JSON)
    response_headers = Column(JSON)
    status_code = Column(Integer)
    is_clone = Column(Boolean, nullable=False)
    timestamp = Column(Float)


    def __init__(self, flow: http.HTTPFlow=None):
        self.id = None
        self.host = None
        self.port = None
        self.http_method = None
        self.url = None
        self.request_body_content = None
        self.response_body_content =None
        self.response_body_size = None
        self.request_body_size = None
        self.body_data_type = None
        self.query = None
        self.body_parameters = None
        self.request_headers = None
        self.response_headers = None
        self.status_code = None
        self.is_clone = None
        self.timestamp = None
        if flow:
            self._flow = flow
            self.id = md5(flow.id)
            self.host = self._flow.request.pretty_host
            self.port = self._flow.request.port
            self.url = self._flow.request.pretty_url
            self.request_headers = dict()     
            
            for k,v in self._flow.request.headers.items():
                self.request_headers[k] = v    
                
            
            self.http_method = self._flow.request.method
            self.is_clone = self._flow.is_replay == "request"
            self.request_body_content = self._flow.request.content
            self.request_body_size = len(self._flow.request.content) if self._flow.request.content else 0
            if self.request_body_content:
                if "content-type" in self._flow.request.headers:
                    self.body_data_type = self._flow.request.headers["content-type"]
                else:
                    self.body_data_type  = "Unknown"
            else:
                self.body_data_type = "undefined"
            
            self.query = None
            self.body_parameters = None
            
            if self._flow.request.query:
                self.query = dict()
                for k,v in self._flow.request.query.items():
                    self.query[k] = v
            
            if self._flow.request.multipart_form:
                self.body_parameters = dict()
                for k,v in self._flow.request.multipart_form.items():
                    self.body_parameters[k.decode()] = v.decode()
            
            if self._flow.request.urlencoded_form:
                self.body_parameters = dict()
                for k,v in self._flow.request.urlencoded_form.items():
                    self.body_parameters[k] = v
            
            if  "json" in self.body_data_type and self.request_body_content:
                self.body_parameters = dict()
                try:
                    json_data= self._flow.request.json()
                    for k,v in json_data.items():
                        self.body_parameters[k] = v
                except:
                    pass
            
            if self._flow.response:
                self.response_body_content = self._flow.response.content
                self.response_body_size = len(self._flow.response.content)
                self.status_code = self._flow.response.status_code
                self.timestamp = self._flow.response.timestamp_end - self._flow.request.timestamp_start
                self.response_headers = dict()
                for k,v in self._flow.response.headers.items():
                    self.response_headers[k] = v    
    
    @classmethod
    def new_flow(cls,http_method:str,url:str,request_body_content:bytes=None,response_body_content:bytes=None,body_data_type:str=None,query:dict[str:str]=None,body_parameters:dict[str:str]=None,request_headers:dict[str:str]=None,response_headers:dict[str:str]=None,status_code:int=None,timestamp:float=None,is_clone:bool=False):
        flow = ObHttpFlow()
        flow.id = md5(f"{http_method}{url}{str(time.time())}")
        flow.host = urlparse(url).hostname
        flow.port = urlparse(url).port
        flow.http_method = http_method
        flow.url = url
        flow.request_body_content = request_body_content
        flow.response_body_content = response_body_content
        flow.response_body_size = len(response_body_content) if response_body_content else None
        flow.request_body_size = len(request_body_content) if request_body_content else None
        flow.body_data_type = body_data_type
        flow.query = query
        flow.body_parameters = body_parameters
        flow.request_headers = request_headers
        flow.response_headers = response_headers
        flow.status_code = status_code
        flow.is_clone = is_clone
        flow.timestamp = timestamp
        return flow
    
    
    def copy(self):
        clone = self._flow.copy()
        ret = ObHttpFlow(flow=clone)
        return ret


    @property
    def in_trace(self):
        return "tag" in self.request_headers

    def has_no_parameters(self):
        return self.query is None and self.body_parameters is None    
    
    
    def get_parameter_value(self,param:str|bytes):

        ret = self.query.get(param,None) if self.query else None
        if ret:
            return ret
        
        ret = self.body_parameters.get(param,None) if self.body_parameters  else None

        return ret
    
    def get_all_parameter_names(self):
        ret = []
        if self.query:
            for name in self.query:
                ret.append(name)
        if self.body_parameters:
            for name in self.body_parameters:
                ret.append(name)
            
        return ret
        
    def export_request(self):
        def pretty_print(req):
            """
            At this point it is completely built and ready
            to be fired; it is "prepared".

            However pay attention at the formatting used in 
            this function because it is programmed to be pretty 
            printed and may differ from the actual request.
            """
            body = req.body.decode() if req.body else None
            if body:
                return('{}\r\n{}\r\n\r\n{}'.format(
                    req.method + ' ' + req.url,
                    '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
                    body,
                ))
            return('{}\r\n{}\r\n\r\n'.format(
                    req.method + ' ' + req.url,
                    '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items())
                ))
        
        ret = None
        try:
            req = requests.Request(self.http_method.upper(),self.url,headers=self.request_headers,data=self.request_body_content)
            ret = req.prepare()
            ret = pretty_print(ret)
        except Exception as e:
            logger.warning(f"An error occur in flow.export_request {str(e)}")
            ret = None
        return ret
    
    def get_parameter_part(self,param):
        
        if self.body_parameters and param in self.body_parameters:
            return "body"
        
        if self.query and param in self.query:
            return "query"
        
        
        """_type = type(param)
        ret = "query" if self._flow.request.query and _type is str and param in self._flow.request.query else None
        if ret:
            return ret
    
        ret = "body" if self._flow.request.urlencoded_form and _type is str and param in self._flow.request.urlencoded_form else None
        
        if ret:
            return ret
        
        ret = "body" if self._flow.request.multipart_form and _type is bytes and param in self._flow.request.multipart_form else None
        
        if ret:
            return ret
        
        
        if "json" in self.body_data_type and self.request_body_content:
            try:
                ret = self._flow.request.json().get(param,None)
            except:
                ret = None
            if ret:
                return "body"""
        return
        
        
