import json
from sqlalchemy import Column, Float, Integer, String, LargeBinary, Boolean, JSON
from persistence.database import Base
from mitmproxy import http
from mitmproxy import ctx
from utilities.util import base64_decode, base64_encode, md5


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
    observer = Column(JSON)

    def __init__(self, flow: http.HTTPFlow):
        # General Info
        self.id = "rid_" + md5(flow.id)
        self.flow = flow
        self.is_clone = flow.is_replay == "request"

        # Parsing Request
        self.request_body_content = flow.request.content
        if self.request_body_content:
            self.request_body_size = len(flow.request.content)
        else:
            self.request_body_size = None

        self.all_parameters = None
        if flow.request.multipart_form:
            self.request_body_parameters = flow.request.multipart_form
            self.request_body_type = "multipart_form"
        elif flow.request.urlencoded_form:
            self.request_body_parameters = flow.request.urlencoded_form
            self.request_body_type = "urlencoded_form"
        elif "content-type" in flow.request.headers and flow.request.headers["content-type"] == "application/json":
            self.request_body_parameters = flow.request.json()
            self.request_body_type = "json"
        else:
            self.request_body_parameters = None
            self.request_body_type = None
        if self.request_body_parameters:
            self.all_parameters = self.request_body_parameters
            self._request_body_parameters = dict()
            for key, value in self.request_body_parameters.items():
                self._request_body_parameters[key] = value

        self.query = flow.request.query
        if self.query:
            self._query = dict()
            for key, value in self.query.items():
                self._query[key] = value
            self.all_parameters = self.query if self.all_parameters is None else self.all_parameters.update(
                self.query)

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

        self.observer = self.request_headers["observer"] if "observer" in self.request_headers else None
        if self.observer:
            data = base64_decode(self.observer)
            self.observer = json.loads(data)
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
        # End

    @property
    def trace_id(self):
        if self.observer and "trace-id" in self.observer:
            return self.observer['trace-id']
        return

    @property
    def vector_id(self):
        if self.observer and "vector-id" in self.observer:
            return self.observer['vector-id']
        return

    @property
    def trace_index(self) -> int:
        if self.observer and "exploit-number" in self.observer and str(self.observer['exploit-number']).isdigit():
            return int(self.observer['exploit-number'])
        return

    @property
    def target_parameters(self):
        if self.observer and "target-parameters" in self.observer:
            return self.observer["target-parameters"]
        return

    def serialize_observer(self):
        if self.observer is None:
            return
        data = json.dumps(self.observer)
        base64_data = base64_encode(data)
        return base64_data

    def empty_request_body(self):
        return self.request_body_content == None

    def in_trace(self):
        return "observer" in self.request_headers

    def copy(self):
        clone = self.flow.copy()
        ret = ObHttpFlow(clone)
        if "view" in ctx.master.addons:
            ctx.master.commands.call("view.flows.add", [clone])
        return ret

    def replay(self):
        ctx.master.commands.call("replay.client", [self.flow])
