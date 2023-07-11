
import logging
import os
import subprocess
import time
from urllib.parse import urlparse
import requests
import url_normalize
from persistence.models.param import Parameter
from persistence.dal import DataAccessLayer
from persistence.models.flow import ObHttpFlow
from definitions import INTRUDER_SERVICE,ROOT_DIR
from utilities.util import find_all_forms,is_absolute_url,is_relative_url,md5
from services.network import encode_data

class ParameterCollector():

    def __init__(self, db_service: DataAccessLayer) -> None:
        self.DAL = db_service
        self.crawled_urls = set()

    async def collect_forms(self, flow: ObHttpFlow):
        if flow.in_trace or flow.no_path_url in self.crawled_urls or flow.response_headers is None or "content-type" not in  flow.response_headers or "html" not in flow.response_headers["content-type"].lower():
            return
        html = flow.response_body_content
        all_forms = find_all_forms(html=html)
        if all_forms:
            for form_dict in all_forms:
                action = form_dict["action"]
                if is_absolute_url(action):
                    endpoint = action
                elif is_relative_url(action):
                    url_parsed = urlparse(flow.url)
                    endpoint =url_normalize.url_normalize(f"{url_parsed.scheme}://{url_parsed.netloc}/{action}")
                else:
                    logging.warning(f"Can not parse a form in {action}")
                    continue
                
                group_id = md5(endpoint+str(time.time()))
                parameters :dict = form_dict["parameters"]
                if form_dict["method"].lower() == "get":
                    part = "query"
                else:
                    part = "body"

                enctype = form_dict["enctype"]
                
                for param_name in parameters.keys():
                    
                    data_type=form_dict["type_map"][param_name]
                    new_parameter = Parameter(name=param_name,http_method=form_dict["method"],data_type=data_type,example_values=[parameters[param_name]],part=part,endpoint=endpoint,original_url=flow.url,group_id=group_id,body_data_type=enctype)
                    await self.DAL.insert_parameter(new_parameter)
                
                headers = flow.request_headers
                if part == "body":
                    encoded_data = encode_data(parameters,enctype=enctype)
                    new_flow : ObHttpFlow = ObHttpFlow.new_flow(http_method=form_dict["method"],url=endpoint,request_body_content=encoded_data,body_parameters=parameters,request_headers=headers,body_data_type=enctype)
                else:
                    new_flow : ObHttpFlow = ObHttpFlow.new_flow(http_method=form_dict["method"],url=endpoint,query=parameters,request_headers=headers,body_data_type=enctype)
                await self.DAL.insert_flow(new_flow)
                await self.DAL.insert_param_flow(flow_id=new_flow.id ,group_id=group_id)     
        self.crawled_urls.add(flow.no_path_url)


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


            # SAVING THE PARAMETER
            if parameter_id not in self.parameter_table:
                saved_parameter : Parameter= await self.DAL.get_parameter_by_id(parameter_id)
                if saved_parameter is None:
                    await self.DAL.insert_parameter( new_parameter=parameter)
                else:
                    group_id = saved_parameter.group
                self.parameter_table[parameter_id] = parameter
            
            await self.DAL.insert_param_flow(group_id=group_id, flow_id=flow.id)

            # START EXPLOITING
            if parameter_id not in self.parameter_table:
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
