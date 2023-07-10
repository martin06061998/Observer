from concurrent.futures import ProcessPoolExecutor
from werkzeug.routing import BaseConverter
from services.intruder.app.parameterservice import *
from quart_cors import route_cors
from utilities.util import base64_encode,md5
from definitions import ROOT_DIR
from quart import Quart, request
from services.intruder.templater.template import build_vector_table
import os
import time
import json
from definitions import ROOT_DIR,INTRUDER_PORT


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

@app.route("/exploit", methods=['POST'])
async def exploit():
    content = await request.get_json()
    app.add_background_task(func=try_exploit, content=content)
    return {"msg": "OK"}


@app.route("/get-parameter-by-id", methods=['POST'])
async def _get_parameter_by_id():
    content = await request.get_json(force=True,silent=True)
    id = content.get("id",None)
    if id is None:
        return {"msg": "invalid data"}
    ret : Parameter = await get_parameter_by_id(id)
    if ret:
        return ret.json()
    return {"msg": "parameter not found"}

@app.route("/get-parameters-by-group-id", methods=['POST'])
async def _get_parameter_by_group_id():
    content = await request.get_json(force=True,silent=True)
    id = content.get("id",None)
    if id is None:
        return {"msg": "invalid data"}
    parameters : list[Parameter] = await get_parameter_by_group_id(id)
    if parameters:
        ret = dict()
        for i,p in enumerate(parameters):
            ret[f"{i}"] = p.json()
        return ret    
    return {"msg": "parameters not found"}

@app.route("/search-parameters", methods=['POST'])
async def _search_parameters():
    content = await request.get_json(force=True,silent=True)
    name = content.get("name","")
    enctype = content.get("enctype","")
    endpoint = content.get("endpoint","")
    data_type = content.get("data_type","")
    limit = content.get("limit",10)
    
    parameters : list[Parameter] = await search_parameters(name=name,enctype=enctype,endpoint=endpoint,data_type=data_type,limit=limit)
    if parameters:
        ret = dict()
        for i,p in enumerate(parameters):
            ret[f"{i}"] = p.json()
        return ret    
    return {"msg": "parameters not found"}

@app.route("/export-request-by-flow-id", methods=['POST'])
async def _get_flow_by_id():
    content = await request.get_json(force=True,silent=True)
    id = content.get("id",None)
    if id is None:
        return {"msg": "invalid data"}
    flow : ObHttpFlow = await get_flow_by_id(id)
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
async def _add_parameter():
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
        await insert_parameter(new_parameter)
        
   
    return {"msg": "parameter not found"}

@app.route("/get-vulnerable-parameters", methods=['POST'])
async def get_vulnerable_parameters_by_bug_type():
    content = await request.get_json(force=True,silent=True)
    if content is None:
        return {"msg":"not valid json"}
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
            "template_path" : r[4],
            "payloads" : r[5]
        }
        

    return reply


def set_process_pool(POOL):
    MAX_WORKER = 6
    POOL = ProcessPoolExecutor(MAX_WORKER)

if __name__ == "__main__":
    set_process_pool(POOL=POOL)
    loop = asyncio.get_event_loop()
    loop.create_task(build_vector_table(vector_list=VECTOR_LIST))
    app.run(port=INTRUDER_PORT, loop=loop,debug=True)
