from persistence.dao.flowdao import FlowDAO
from persistence.dao.paramdao import ParameterDao
from persistence.models.flow import ObHttpFlow
from persistence.models.param import Parameter,ParamFlowMap
from persistence.models.testresult import TestResult
from persistence.dao.testresultdao import TestResultDao

class DataAccessLayer():
    """This class is responsible for connecting to the database and executing queries"""

    def __init__(self):
        self.db_services = dict()
        self.db_services["flow"] = FlowDAO()
        self.db_services['parameter'] = ParameterDao()
        self.db_services['testresults'] = TestResultDao()

    # FLOW DAL
    async def get_flow_by_id(self, id: str) -> ObHttpFlow:
        service = self.db_services["flow"]
        ret: ObHttpFlow = await service.get_flow_by_id(id)
        return ret

    async def insert_flow(self, flow: ObHttpFlow):
        service = self.db_services["flow"]
        ret: ObHttpFlow = await service.insert_flow(flow)
        return ret

    # END

    # PARAMETER DAL
    async def insert_parameter(self, new_parameter=None):
        service = self.db_services["parameter"]
        ret: Parameter = await service.insert_parameter(new_parameter=new_parameter)
        return ret

    async def get_parameter_by_id(self, id: str) -> Parameter:
        service = self.db_services["parameter"]
        ret: Parameter = await service.get_parameter_by_id(id)
        return ret
    
    async def get_parameters_by_group_id(self,id:str)->list[Parameter]:
        service = self.db_services["parameter"]
        ret: list[Parameter] = await service.get_parameters_by_group_id(id)
        return ret
    
    async def get_parameters_by_name(self,name:str)->list[Parameter]:
        service = self.db_services["parameter"]
        ret: list[Parameter] = await service.get_parameters_by_name(name)
        return ret

    async def add_param_flow(self, parameter_id: str, flow_id: str):
        service = self.db_services["parameter"]
        return await service.add_param_flow(parameter_id, flow_id)
    
    async def get_last_param_flow(self, parameter_id: str) -> ParamFlowMap:
        service = self.db_services["parameter"]
        ret: ParamFlowMap = await service.get_last_param_flow(parameter_id)
        return ret
    # END
    
    #TEST RESULT DAO
    async def insert_test_result(self, test_result:TestResult):
        service = self.db_services["testresults"]
        ret: TestResult = await service.insert_test_result(test_result)
        return ret
    
    async def search_vulnerable_parameters_by_bug_type(self,name,endpoint,bug_type,is_vulnerable,is_tested,limit,template_path):
        service = self.db_services["testresults"]
        ret: list[TestResult] = await service.search_vulnerable_parameters_by_bug_type(name,endpoint,bug_type,is_vulnerable,is_tested,limit,template_path)
        return ret
    #END
    

def get_data_access_layer_instance():
    return DataAccessLayer()