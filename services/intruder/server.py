import asyncio
import copy
import glob
import logging
from quart import Quart, request
import sys
import os
from werkzeug.routing import BaseConverter

import requests


def init_vector_table():
    current = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(os.path.join(current, '../../'))
    from persistence.models.attackvector import AttackVector
    from services.intruder.templater.template import parse_template
    from definitions import ROOT_DIR
    vector_table: dict[str:AttackVector]
    vector_table = dict()
    for path in glob.glob(pathname=os.path.join(ROOT_DIR, 'services', 'intruder',  'templater', 'recipe', '**', '*.yaml'), recursive=True):
        newTemplate = parse_template(path)
        if newTemplate is None:
            continue
        for vector in newTemplate.vectors:
            vector_table[vector.id] = vector
    return vector_table


def get_data_access_layer_instance():
    current = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(os.path.join(current, '../../'))
    from persistence.dal import DataAccessLayer
    return DataAccessLayer()


vector_table = init_vector_table()
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
    current = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(os.path.join(current, '../../'))
    from persistence.models.attackvector import AttackVector
    from persistence.models.attackvector import Exploit
    from persistence.models.flow import ObHttpFlow
    import aiofiles as aiof

    dal = get_data_access_layer_instance()
    flow_id = content["flow_id"]
    parameter_id = content["parameter_id"]
    saved_param = await dal.get_parameter_by_id(parameter_id)
    if saved_param is None:
        return
    saved_flow = await dal.get_flow_by_id(flow_id)
    if saved_flow is None:
        return
    vector: AttackVector
    for vector in vector_table.values():
        if not vector.match(saved_param):
            # logging.warning(f"{saved_param.name} not match {vector.path}")
            continue
        end_point = saved_flow.request_scheme+"://" + \
            saved_flow.request_host+saved_flow.request_path
        proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080"
        }
        headers = saved_flow._request_headers
        headers["tag"] = vector.bug_type
        flow_sequence = [saved_flow]
        pattern = ""
        if saved_flow.http_method.lower() == "get":
            params = copy.deepcopy(saved_flow._query)
            pattern = copy.deepcopy(params[saved_param.name])
            exploit: Exploit
            for exploit in vector.exploit_sequence:
                if exploit is None:
                    continue
                payload = exploit.payload
                if payload is None:
                    continue
                rendered_payload = payload.render(pattern)
                params[saved_param.name] = rendered_payload
                ret = requests.get(url=end_point, proxies=proxies, headers=headers,
                                   params=params, verify=False, timeout=14)

                new_flow = ObHttpFlow(request_scheme=saved_flow.request_scheme, request_host=saved_flow.request_host, request_path=saved_flow.request_path, http_method=saved_flow.http_method, url=saved_flow.url,
                                      status_code=ret.status_code, timestamp=ret.elapsed.total_seconds(), request_headers=headers, response_headers=ret.headers, response_body_content=ret.content, query=params)
                flow_sequence.append(new_flow)
        else:
            end_point = saved_flow.url
            body_parameters = copy.deepcopy(
                saved_flow._request_body_parameters)
            pattern = copy.deepcopy(body_parameters[saved_param.name])
            exploit: Exploit
            for exploit in vector.exploit_sequence:
                if exploit is None:
                    continue
                payload = exploit.payload
                if payload is None:
                    continue
                rendered_payload = payload.render(pattern)
                body_parameters[saved_param.name] = rendered_payload


                ret = requests.post(url=end_point, headers=headers,data=body_parameters, verify=False, timeout=14)
                new_flow = ObHttpFlow(request_scheme=saved_flow.request_scheme, request_host=saved_flow.request_host, request_path=saved_flow.request_path, http_method=saved_flow.http_method, url=saved_flow.url,
                                      status_code=ret.status_code, timestamp=ret.elapsed.total_seconds(), request_headers=headers, response_headers=ret.headers, response_body_content=ret.content, request_body_parameters=body_parameters)
                flow_sequence.append(new_flow)

        isVulnerable = vector.verify(flow_sequence=flow_sequence)
        if isVulnerable:
            async with aiof.open("bug.log", "a+") as f:
                await f.write(f"Bug type: {vector.bug_type}\n")
                await f.write(f"Path: {vector.path}\n")
                await f.write(f"Parameter: {saved_param.name}\n")
                for i, exploit in enumerate(vector.exploit_sequence):
                    if exploit is None:
                        continue
                    payload = exploit.payload
                    if payload is None:
                        continue
                    await f.write(f"Payload {i}: {payload.render(pattern)}\n")
                await f.write(f"="*125+"\n\n")
                await f.flush()


@app.route("/exploit", methods=['POST'])
async def exploit():
    content = await request.get_json()
    app.add_background_task(func=try_exploit, content=content)
    return {"msg": "OK"}


@app.route("/result/<regex('[a-fA-F0-9]{32}'):param>/")
async def result(param):
    return {"msg": "OK"}

if __name__ == "__main__":
    app.run(port=5555)
