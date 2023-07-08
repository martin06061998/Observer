
import logging
import os
import subprocess
import time
import requests
import url_normalize
from persistence.models.param import Parameter
from persistence.dal import DataAccessLayer
from persistence.models.flow import ObHttpFlow
from definitions import INTRUDER_SERVICE,ROOT_DIR
from utilities.util import find_all_forms,is_absolute_url,is_relative_url,md5
from mitmproxy.http import Request 

class ParameterCollector():

    def __init__(self, db_service: DataAccessLayer) -> None:
        self.DAL = db_service
        self.crawled_urls = set()

    async def collect_forms(self, flow: ObHttpFlow):
        if flow.url in self.crawled_urls or flow.response_headers is None or "content-type" not in  flow.response_headers or "html" not in flow.response_headers["content-type"].lower():
            return
        
        html = flow.response_body_content
        all_forms = find_all_forms(html=html)

        if all_forms:
            
            for form_dict in all_forms:
                action = form_dict["action"]
                if is_absolute_url(action):
                    endpoint = action
                elif is_relative_url(action):
                    endpoint =url_normalize.url_normalize(f"{flow.url}{action}")
                else:
                    logging.warning(f"Can not parse a form in {action}")
                    continue
                
                group_id = md5(endpoint+str(time.time()))
                parameters :dict = form_dict["parameters"]

                enctype = form_dict["enctype"]


                for param_name in parameters.keys():
                    if param_name:
                        data_type=form_dict["type_map"][param_name]
                        new_parameter = Parameter(name=param_name,http_method="post",data_type=data_type,example_values=[parameters[param_name]],part="body",endpoint=endpoint,original_url=flow.url,group_id=group_id,body_data_type=enctype)
                        await self.DAL.insert_parameter(new_parameter)
        
        self.crawled_urls.add(flow.url)


class BugAnalyzer():
    """This class is responsible for analyzing the request and response for vulnerabilities. Do not use this class directly, use ObserverServiceAPI instead"""

    def __init__(self, db_service: DataAccessLayer) -> None:
        self.parameter_table: dict[str:Parameter] = dict()
        self.DAL = db_service

    async def try_exploit(self, parameter_id: str):
        end_point = INTRUDER_SERVICE + "/exploit"
        data = {
            "parameter_id": parameter_id,
        }
        r = requests.post(url=end_point, json=data)

    async def analyze(self, flow: ObHttpFlow) -> None:
        #logging.warning(flow.url)

        group_id = md5(flow.url+str(time.time()))
        
        for param in flow.get_all_parameter_names():
            parameter = Parameter(name=param,http_method=flow.http_method,example_values=[flow.get_parameter_value(param)],part=flow.get_parameter_part(param),group_id=group_id,original_url=flow.url,endpoint=flow.url,body_data_type=flow.body_data_type)
            parameter_id = parameter.id
            if parameter_id in self.parameter_table:
                continue

            # SAVING THE PARAMETER
            await self.DAL.insert_parameter( new_parameter=parameter)

            self.parameter_table[parameter_id] = parameter
            
            await self.DAL.add_param_flow(parameter_id=parameter_id, flow_id=flow.id)

            # START EXPLOITING
            await self.try_exploit(parameter_id=parameter_id)

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
        #crawler = subprocess.Popen(
        #    ["Scripts\python.exe", os.path.join(ROOT_DIR,"services\crawler\server.py")],stdout=nul,stderr=nul)
        self.services.append(intruder)
        #self.services.append(crawler)


    def clean(self):
        for s in self.services:
            s.terminate()

    async def handle_request(self, flow: ObHttpFlow):
        pass

    async def handle_response(self, flow: ObHttpFlow):
        await self.PARAMETER_COLLECTOR.collect_forms(flow)

        if flow.in_trace  or flow.has_no_parameters():
            return

        await self.DAL.insert_flow(flow)

        await self.ANALYZER.analyze(flow)
        # self.INJECTOR.handle_response(flow)
