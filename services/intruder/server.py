import asyncio
import copy
import logging
from utilities.util import dict_to_url_encoded
from quart import Quart, request
from werkzeug.routing import BaseConverter
from services.intruder.templater.template import build_vector_table
from persistence.dal import get_data_access_layer_instance
from services.intruder.render import render_html
import aiofiles as aiof
from persistence.models.attackvector import Exploit,AttackVector
from persistence.models.flow import ObHttpFlow


vector_table =  dict()
app = Quart(__name__)
logging.basicConfig(filename="error.log",
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
    await asyncio.sleep(0.3)

    # PREPARE DATA BEFORE ASSESSMENT
    dal = get_data_access_layer_instance()
    flow_id = content["flow_id"]
    parameter_id = content["parameter_id"]
    saved_param = await dal.get_parameter_by_id(parameter_id)
    if saved_param is None:
        return
    saved_flow = await dal.get_flow_by_id(flow_id)
    if saved_flow is None:
        return
    # END
    
    vector: AttackVector
    for vector in vector_table.values():
        if not vector.match(saved_param):
            continue
        base_url = saved_flow.request_scheme+"://" + saved_flow.request_host
        end_point = base_url+saved_flow.request_path

        #proxies = {
        #    "http://": "http://127.0.0.1:8080",
        #    "https://": "http://127.0.0.1:8080"
        #}
        
        headers: dict = saved_flow._request_headers
        headers["tag"] = vector.bug_type
        headers.pop("content-length",None)
        flow_sequence = [saved_flow]
        method = saved_param.http_method
        params = None
        data=None
        pattern = None
        encoded_params = None
        encoded_data = None
        
        # HANDLE GET REQUEST(I.E HANDLE URL PARAMETERS)
        if saved_param.part == "query":
            params = copy.deepcopy(saved_flow._query)
            pattern = copy.deepcopy(params[saved_param.name])
        else:
            data = copy.deepcopy(saved_flow._request_body_parameters)
            pattern = copy.deepcopy(data[saved_param.name])

        
        exploit: Exploit
        for exploit in vector.exploit_sequence:
            if exploit is None:
                continue
            payload = exploit.payload
            if payload is None:
                continue
            rendered_payload = payload.render(pattern)
            if params:
                params[saved_param.name] = rendered_payload
                encoded_params = dict_to_url_encoded(params)
            if data:
                data[saved_param.name] = rendered_payload
                encoded_data = dict_to_url_encoded(data=data)
            
            r = await render_html(method=method,base_url=end_point,headers=headers,params=encoded_params,data=encoded_data)
      
            new_flow = ObHttpFlow(request_scheme=saved_flow.request_scheme, request_host=saved_flow.request_host, request_path=saved_flow.request_path, http_method=saved_flow.http_method, url=saved_flow.url,
                                      status_code=r.get("status_code"), timestamp=r.get("elapsed"), request_headers=headers, response_headers=r.get("headers"), response_body_content=r.get("content"), query=params)
            flow_sequence.append(new_flow)
            # END

        # VULNERABILITY ASSESSMENT
        isVulnerable = vector.verify(flow_sequence=flow_sequence)
        # END

        # REPORT BUG
        if isVulnerable:
            async with aiof.open("bug.log", "a+") as f:
                await f.write(f"Bug type: {vector.bug_type}\n")
                await f.write(f"Template Path: {vector.path}\n")
                await f.write(f"Parameter: {saved_param.name}\n")
                await f.write(f"Flow id: {saved_flow.id}\n")
                for i, exploit in enumerate(vector.exploit_sequence):
                    if exploit is None:
                        continue
                    payload = exploit.payload
                    if payload is None:
                        continue
                    await f.write(f"Payload {i}: {payload.render(pattern)}\n")
                await f.write(f"="*125+"\n\n")
                await f.flush()
        # END
        await asyncio.sleep(0.4)


@app.route("/exploit", methods=['POST'])
async def exploit():
    content = await request.get_json()
    app.add_background_task(func=try_exploit, content=content)
    return {"msg": "OK"}


@app.route("/result/<regex('[a-fA-F0-9]{32}'):param>/")
async def result(param):
    return {"msg": "OK"}


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.create_task(build_vector_table(vector_table=vector_table))
    app.run(port=5555, loop=loop,debug=True)
