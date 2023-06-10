
import os
import subprocess
import requests
from persistence.models.param import Parameter
from persistence.dal import DataAccessLayer
from persistence.models.flow import ObHttpFlow


class BugAnalyzer():
    """This class is responsible for analyzing the request and response for vulnerabilities. Do not use this class directly, use ObserverServiceAPI instead"""

    def __init__(self, db_service: DataAccessLayer) -> None:
        self.parameter_table: dict[str:Parameter] = dict()
        self.DAL = db_service

    async def try_exploit(self, parameter_id: str, flow_id: str):
        end_point = f"http://127.0.0.1:5555/exploit"
        data = {
            "parameter_id": parameter_id,
            "flow_id": flow_id
        }
        r = requests.post(url=end_point, json=data)


    async def analyze(self, flow: ObHttpFlow) -> None:
        for param in flow.all_parameters.keys():
            parameter_id = Parameter.calculate_id(
                param, flow.http_method, flow.request_scheme, flow.request_host, flow.request_path)

            # SKIP IF THE PARAMETER HAS BEEN EXPLOITED
            if parameter_id in self.parameter_table:
                continue

            # SAVING THE PARAMETER
            saved_parameter = await self.DAL.get_parameter_by_id(parameter_id)
            if saved_parameter is None:
                new_parameter = Parameter.new_parameter(
                    param=param, flow=flow)
                await self.DAL.insert_parameter(new_parameter)
                self.parameter_table[parameter_id] = new_parameter
            else:
                self.parameter_table[parameter_id] = saved_parameter

            await self.DAL.add_param_flow(parameter_id=parameter_id, flow_id=flow.id)
            # START EXPLOITING
            await self.try_exploit(parameter_id=parameter_id, flow_id=flow.id)


class Observer:
    def __init__(self) -> None:
        # Collect all attack templates
        db_service = DataAccessLayer()
        self.ANALYZER = BugAnalyzer(db_service)
        self.DAL = db_service
        self.services = []
        nul = open(os.devnull, "w")
        intruder = subprocess.Popen(
            ["Scripts\python.exe", "services\intruder\server.py"], stdout=nul, stderr=nul)
        crawler = subprocess.Popen(
            ["Scripts\python.exe", "services\crawler\server.py"], stdout=nul, stderr=nul)
        self.services.append(intruder)
        self.services.append(crawler)

    def clean(self):
        for s in self.services:
            s.terminate()

    async def handle_request(self, flow: ObHttpFlow):
        pass

    async def handle_response(self, flow: ObHttpFlow):
        if flow.in_trace() or flow.is_replayed():
            return
        await self.DAL.insert_flow(flow)
        await self.ANALYZER.analyze(flow)
        # self.INJECTOR.handle_response(flow)
