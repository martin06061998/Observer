from persistence.dao.flowdao import FlowDAO
from persistence.dao.paramdao import ParameterDao
from persistence.models.flow import ObHttpFlow
from persistence.models.param import Parameter,ParamFlowMap


class DataAccessLayer():
    """This class is responsible for connecting to the database and executing queries"""

    def __init__(self):
        self.db_services = dict()
        self.db_services["flow"] = FlowDAO()
        self.db_services['parameter'] = ParameterDao()

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
    

def get_data_access_layer_instance():
    return DataAccessLayer()