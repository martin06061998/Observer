
import logging
from persistence.dao.flowdao import FlowDAO
from persistence.dao.inputdao import InputDao
from persistence.dao.tracedao import TraceDAO
from persistence.models.flow import ObHttpFlow
from persistence.models.file import PickleFile

from persistence.models.trace import InputTrace


class DataAccessLayer():
    """This class is responsible for connecting to the database and executing queries"""

    def __init__(self):
        self.db_services = dict()
        self.db_services["flow"] = FlowDAO()
        self.db_services["trace"] = TraceDAO()
        self.db_services['input'] = InputDao()

    def clean(self):
        for service in self.db_services.values():
            service.clean()

    def get_flow_by_id(self, id: str) -> ObHttpFlow:
        service = self.db_services["flow"]
        return service.get_flow_by_id(id)

    def insert_flow(self, flow: ObHttpFlow):
        service = self.db_services["flow"]
        return service.insert_flow(flow)

    def insert_pickle_file(self, path: str, data, last_modified: float):
        service = self.db_services["flow"]
        return service.insert_pickle_file(path, data, last_modified)

    def update_pickle_file(self, path: str, data, last_modified: float):
        service = self.db_services["flow"]
        return service.update_pickle_file(path, data, last_modified)

    def get_pickle_file_by_path(self, path) -> PickleFile:
        service = self.db_services["flow"]
        return service.get_pickle_file_by_path(path)

    def insert_input(self, new_input=None, param: str = None, example_values: list[str] = None, flow: ObHttpFlow = None):
        service = self.db_services["input"]
        return service.insert_input(new_input=new_input, param=param, example_values=example_values, flow=flow)

    def get_input_by_id(self, id: str):
        service = self.db_services["input"]
        return service.get_input_by_id(id)

    def insert_trace(self, new_trace: InputTrace):
        service = self.db_services["trace"]
        return service.insert_trace(new_trace)

    def insert_flow_id_to_trace(self, trace_id: str, flow_id: str):
        service = self.db_services["trace"]
        return service.insert_flow_id_to_trace(trace_id, flow_id)

    def get_flow_by_trace_id(self, trace_id: str, index: int):
        service = self.db_services["trace"]
        return service.get_flow_by_trace_id(trace_id, index)

    def get_trace_by_id(self, id: int):
        service = self.db_services["trace"]
        return service.get_trace_by_id(id)
    
    
    def add_example_value(self,id:str,value:str):
        service = self.db_services["input"]
        return service.add_example_value(id,value)