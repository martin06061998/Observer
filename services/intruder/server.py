import asyncio
import base64
import json
import logging
import multiprocessing
import os
import time
from quart import Quart, request
from quart_cors import route_cors
from werkzeug.routing import BaseConverter
from services.intruder.templater.template import build_vector_table
from persistence.dal import get_data_access_layer_instance
from persistence.models.attackvector import AttackVector
from definitions import INTRUDER_PORT
from concurrent.futures import ProcessPoolExecutor
from persistence.models.param import Parameter
from persistence.models.flow import ObHttpFlow
from utilities.util import base64_encode,md5
from quart import send_file
from definitions import ROOT_DIR
from persistence.models.testresult import TestResult

vector_list : list[AttackVector]=  []
loop = None
LIMIT = 4
POOL = None
m = None
lock = None

#process_pool: list[Process] = []
#SEMAPHORE = asyncio.Semaphore(3*LIMIT)
app = Quart(__name__)

logging.basicConfig(filename=os.path.join(ROOT_DIR,"log","intruder.log"),
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.WARNING)


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]

app.url_map.converters['regex'] = RegexConverter




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

    flow_map = await dal.get_last_param_flow(parameter_id=parameter_id)
    
    if flow_map is None:
        logging.warning(f"Cannot find any flow for {parameter_id}")
        return

    saved_flow =  await dal.get_flow_by_id(flow_map.flow_id)

    TASKS = []
    force = content.get("force",False)
    for vector in vector_list:
        TASKS.append(loop.run_in_executor(POOL, vector.exploit, saved_flow,saved_param,lock,force))
   
    
    await asyncio.gather(*TASKS)
    t:asyncio.Future
    for t in TASKS:
        test_result = TestResult(**t.result())
        await dal.insert_test_result(test_result)
        

async def __get_parameter_by_id(id:str):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    dal = get_data_access_layer_instance()
    
    parameter:Parameter = await dal.get_parameter_by_id(id)
    
    return parameter

async def __get_parameter_by_group_id(id:str):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    dal = get_data_access_layer_instance()
    
    parameters:Parameter = await dal.get_parameters_by_group_id(id)
    
    return parameters

async def __get_parameters_by_name(name:str):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    dal = get_data_access_layer_instance()
    
    parameters:Parameter = await dal.get_parameters_by_name(name)
    
    return parameters

async def __get_flow_by_id(id:str):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    dal = get_data_access_layer_instance()
    
    flow:ObHttpFlow = await dal.get_flow_by_id(id)
    
    return flow

async def __insert_parameter(new_parameter):
    dal = get_data_access_layer_instance()
    
    await dal.insert_parameter(new_parameter)


@app.route("/exploit", methods=['POST'])
async def exploit():
    content = await request.get_json()
    app.add_background_task(func=try_exploit, content=content)
    return {"msg": "OK"}


@app.route("/get-parameter-by-id", methods=['POST'])
async def get_parameter_by_id():
    content = await request.get_json(force=True,silent=True)
    id = content.get("id",None)
    if id is None:
        return {"msg": "invalid data"}
    ret : Parameter = await __get_parameter_by_id(id)
    if ret:
        return ret.json()
    return {"msg": "parameter not found"}

@app.route("/get-parameters-by-group-id", methods=['POST'])
async def get_parameter_by_group_id():
    content = await request.get_json(force=True,silent=True)
    id = content.get("id",None)
    if id is None:
        return {"msg": "invalid data"}
    parameters : list[Parameter] = await __get_parameter_by_group_id(id)
    if parameters:
        ret = dict()
        for i,p in enumerate(parameters):
            ret[f"{i}"] = p.json()
        return ret    
    return {"msg": "parameters not found"}

@app.route("/get-parameters-by-name", methods=['POST'])
async def get_parameters_by_name():
    content = await request.get_json(force=True,silent=True)
    name = content.get("name",None)
    if name is None:
        return {"msg": "invalid data"}
    parameters : list[Parameter] = await __get_parameters_by_name(name)
    if parameters:
        ret = dict()
        for i,p in enumerate(parameters):
            ret[f"{i}"] = p.json()
        return ret    
    return {"msg": "parameters not found"}

@app.route("/export-request-by-flow-id", methods=['POST'])
async def get_flow_by_id():
    content = await request.get_json(force=True,silent=True)
    id = content.get("id",None)
    if id is None:
        return {"msg": "invalid data"}
    flow : ObHttpFlow = await __get_flow_by_id(id)
    if flow:
        raw_request = flow.export_request()
        if raw_request:
            encoded = base64_encode(raw_request)
            return {"data":encoded}
    return {"msg": "flow not found"}

@app.route("/", methods=['POST','GET'])
@route_cors(allow_origin="*")
async def index():
    return{"msg":"ok"}

@app.route("/add-parameter", methods=['POST'])
@route_cors(allow_origin="*")
async def add_parameter():
    content :dict = await request.get_json(force=True,silent=True)

    endpoint = content.get("endpoint",None)
    if endpoint is None:
        return {"msg": "endpoint can not be none"}
    original_url = content.get("original_url",None)
    if original_url is None:
        return {"msg": "original_url can not be none"}
    data:dict= content.get("data",None)
    if data is None:
        return {"msg": "data cannot be none"}
    method = data.get("method",None)
    if method is None:
        return {"msg": "method cannot be none"}
    body : dict = data.get("body",None)
    if body is None:
        return {"msg": "body can not be none"}

    body = json.loads(body)
    group_id = md5(original_url+str(time.time()))
    for name,value in body.items():
        new_parameter :  Parameter = Parameter(name=name,http_method=method,original_url=original_url,endpoint=endpoint,example_values=[value],group_id=group_id,part="body")
        await __insert_parameter(new_parameter)
        
   
    return {"msg": "parameter not found"}

@app.route("/get-vulnerable-parameters", methods=['POST'])
async def get_vulnerable_parameters_by_bug_type():
    content = await request.get_json(force=True,silent=True)
    bug_type = content.get("bug_type","")
    endpoint = content.get("endpoint","")
    name = content.get("name",None)
    is_vulnerable = content.get("is_vulnerable",True)
    limit = content.get("limit",10)
    is_tested = content.get("is_tested",True)
    template_path = content.get("template_path","")
    
    dal = get_data_access_layer_instance()
    
    ret = await dal.search_vulnerable_parameters_by_bug_type(name,endpoint,bug_type,is_vulnerable,is_tested,limit,template_path)
    reply = {}
    for i,r in enumerate(ret):
        reply[i] = {
            "parameter_id":r[0],
            "parameter_name":r[1],
            "endpoint":r[2],
            "bug_type":r[3],
            "template_path" : r[4]
        }
        
    #logging.warning(ret)
    return reply




if __name__ == "__main__":
    POOL = ProcessPoolExecutor(max_workers=LIMIT)
    m = multiprocessing.Manager()
    lock = m.Lock()
    loop = asyncio.get_event_loop()
    loop.create_task(build_vector_table(vector_list=vector_list))
    app.run(port=INTRUDER_PORT, loop=loop,debug=True)
