
import logging
import os
import subprocess
import requests
from persistence.models.param import Parameter
from persistence.dal import DataAccessLayer
from persistence.models.flow import ObHttpFlow
from definitions import INTRUDER_SERVICE,ROOT_DIR
from utilities.util import find_all_forms,is_absolute_url,is_relative_url
from mitmproxy.http import Request 




class ParameterCollector():

    def __init__(self, db_service: DataAccessLayer) -> None:
        self.DAL = db_service
        self.crawled_urls = set()

    async def collect_forms(self, flow: ObHttpFlow):
        if flow.url in self.crawled_urls or flow.response_headers is None or "content-type" not in  flow.response_headers or "html" not in flow.response_headers["content-type"].lower():
            return
        
        html = flow.response_body_content
        clone = flow.copy()
        all_forms = find_all_forms(html=html)

        if all_forms:
            for form_dict in all_forms:
                action = form_dict["action"]
                if is_absolute_url(action):
                    endpoint = action
                elif is_relative_url(action):
                    endpoint = f"{clone.request_scheme}://{clone.request_host}{action}"
                else:
                    logging.warning(f"Can not parse a form in {action}")
                    continue
                
                logging.warning(endpoint)

                clone.http_method = "post"
                parameters :dict = form_dict["parameters"]

                enctype = form_dict["enctype"]
                r = Request.make(method="post",url="http://example.com",headers=clone.request_headers)
                clone._flow.request = r
                if enctype == "application/x-www-form-urlencoded":
                    r.urlencoded_form.update(parameters)
                    clone.request_body_parameters = r.urlencoded_form
                if enctype == "multipart/form-data":
                    encoded_parameters = {}
                    for key,value in parameters.items():
                        encoded_key = key.encode()
                        encoded_value = value.encode()
                        encoded_parameters[encoded_key] = encoded_value
                    r.multipart_form.update(encoded_parameters)
                    clone.request_body_parameters = r.multipart_form
                clone.all_parameters = clone.request_body_parameters

                clone.request_body_type = enctype
                clone.request_body_size = len(clone.request_body_content)
                clone._request_body_parameters = parameters
                clone.request_body_content = r.content
                clone.response_body_content = b""
                clone._response_headers = {}
                clone.response_body_size = 0

                await self.DAL.insert_flow(flow=clone)

                for param in parameters.keys():
                    new_parameter = Parameter.new_parameter(param=param, flow=clone,endpoint=endpoint,data_type=form_dict["type_map"][param])
                    # SAVING THE PARAMETER
                    saved_parameter = await self.DAL.get_parameter_by_id(new_parameter.id)
                    if saved_parameter is None:
                        await self.DAL.insert_parameter(new_parameter)
        
        self.crawled_urls.add(flow.url)


class BugAnalyzer():
    """This class is responsible for analyzing the request and response for vulnerabilities. Do not use this class directly, use ObserverServiceAPI instead"""

    def __init__(self, db_service: DataAccessLayer) -> None:
        self.parameter_table: dict[str:Parameter] = dict()
        self.DAL = db_service

    async def try_exploit(self, parameter_id: str, flow_id: str):
        end_point = INTRUDER_SERVICE + "/exploit"
        data = {
            "parameter_id": parameter_id,
        }
        r = requests.post(url=end_point, json=data)

    async def analyze(self, flow: ObHttpFlow) -> None:
        if flow.all_parameters is None:
            return
        for param in flow.all_parameters.keys():
            parameter = Parameter.new_parameter(
                param=param, flow=flow)

            parameter_id = parameter.id
            if parameter_id in self.parameter_table:
                continue

            # SAVING THE PARAMETER
            saved_parameter = await self.DAL.get_parameter_by_id(parameter_id)
            if saved_parameter is None:
                await self.DAL.insert_parameter(parameter)

            self.parameter_table[parameter_id] = parameter
            #await self.DAL.add_param_flow(parameter_id=parameter_id, flow_id=flow.id)

            # START EXPLOITING
            await self.try_exploit(parameter_id=parameter_id, flow_id=flow.id)

class Observer:
    def __init__(self) -> None:
        # Collect all attack templates
        db_service = DataAccessLayer()
        self.ANALYZER = BugAnalyzer(db_service)
        self.PARAMETER_COLLECTOR = ParameterCollector(db_service=db_service)
        self.DAL = db_service
        self.services = []
        nul = open(os.devnull, "w")
        intruder = subprocess.Popen(
            ["Scripts\python.exe", os.path.join(ROOT_DIR,"services\intruder\server.py")],stdout=nul,stderr=nul)
        crawler = subprocess.Popen(
            ["Scripts\python.exe", os.path.join(ROOT_DIR,"services\crawler\server.py")],stdout=nul,stderr=nul)
        self.services.append(intruder)
        self.services.append(crawler)


    def clean(self):
        for s in self.services:
            s.terminate()

    async def handle_request(self, flow: ObHttpFlow):
        pass

    async def handle_response(self, flow: ObHttpFlow):
        
        await self.PARAMETER_COLLECTOR.collect_forms(flow)

        if flow.in_trace() or flow.is_replayed() or flow.all_parameters is None:
            return
        await self.DAL.insert_flow(flow)

        await self.ANALYZER.analyze(flow)
        # self.INJECTOR.handle_response(flow)
