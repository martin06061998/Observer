import asyncio
import logging
from persistence.dal import get_data_access_layer_instance
from persistence.models.attackvector import AttackVector
from persistence.models.param import Parameter
from persistence.models.flow import ObHttpFlow
from persistence.models.testresult import TestResult


POOL = None
VECTOR_LIST:list[AttackVector] = []

async def try_exploit(content: dict[str, str]):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    await asyncio.sleep(0.2)

    # PREPARE DATA BEFORE ASSESSMENT
    dal = get_data_access_layer_instance()
    
    parameter_id = content["parameter_id"]
    saved_param = await dal.get_parameter_by_id(parameter_id)

    if saved_param is None:
        logging.warning(f"parameter id {parameter_id} not exists")
        return

    saved_flow = await dal.get_last_param_flow(group_id=saved_param.group)
    
    if saved_flow is None:
        logging.warning(f"Cannot find any flow for {parameter_id}")
        return



    TASKS = []
    force = content.get("force",False)
    loop = asyncio.get_event_loop()
    for vector in VECTOR_LIST:
        TASKS.append(loop.run_in_executor(POOL, vector.exploit, saved_flow,saved_param,force))
   
    
    await asyncio.gather(*TASKS)
    t:asyncio.Future
    for t in TASKS:
        test_result = TestResult(**t.result())
        await dal.insert_test_result(test_result)
        

async def get_parameter_by_id(id:str):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    dal = get_data_access_layer_instance()
    
    parameter:Parameter = await dal.get_parameter_by_id(id)
    
    return parameter

async def get_parameter_by_group_id(id:str):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    dal = get_data_access_layer_instance()
    
    parameters:Parameter = await dal.get_parameters_by_group_id(id)
    
    return parameters

async def search_parameters(name:str,enctype:str,endpoint:str,data_type:str,limit:int):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    dal = get_data_access_layer_instance()
    
    parameters:Parameter = await dal.search_parameters(name,enctype,endpoint,data_type,limit)
    
    return parameters

async def get_flow_by_id(id:str):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    dal = get_data_access_layer_instance()
    
    flow:ObHttpFlow = await dal.get_flow_by_id(id)
    
    return flow

async def insert_parameter(new_parameter):
    dal = get_data_access_layer_instance()
    
    await dal.insert_parameter(new_parameter)
    
