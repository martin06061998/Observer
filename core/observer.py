import copy
import glob
import inspect
import logging
import os
import re
from core.analyzer.asserter.assertserviceapi import AsserterServiceAPI
from core.templater.template import parse_template
from definitions import PLACEHOLDER, ROOT_DIR, BUILDIN
from persistence.models.attackvector import AttackVector, Exploit
from persistence.models.input import Input as i
from persistence.dal import DataAccessLayer
from persistence.models.trace import InputTrace
from persistence.models.flow import ObHttpFlow


class BaseModule:

    def __init__(self, vector_table, db_service) -> None:
        self.vector_table: dict[str:AttackVector] = vector_table
        self.DB = db_service


class BugAnalyzer(BaseModule):
    """This class is responsible for analyzing the request and response for vulnerabilities. Do not use this class directly, use ObserverServiceAPI instead"""

    def __init__(self, vector_table: dict[str:AttackVector], db_service) -> None:
        super().__init__(vector_table, db_service)
        self.inputs: dict[str:i] = dict()

    def report_bug(self, trace_id: int):
        trace: InputTrace = self.DB.get_trace_by_id(trace_id)
        if trace is None:
            logging.warning(
                "data error, trace not found [observer.py:report_bug:111]")
            return
        input_id = trace.input_id
        saved_input: i = self.DB.get_input_by_id(input_id)
        if saved_input is None:
            logging.warning(
                "data error, input not found [observer.py:report_bug:116]")
            return
        vector_id = trace.vector_id
        vector: AttackVector = self.vector_table[vector_id]
        exploit: Exploit = vector.vector[-1]

        with open(os.path.join(ROOT_DIR, 'bug.log'), '+a') as f:
            f.write(f"Bug type: {vector.bug_type}\n")
            f.write(f"Input name: {saved_input.name}" + "\n")
            f.write(
                f"Endpoint: {saved_input.http_method} {saved_input.scheme}://{saved_input.host}/{saved_input.path}" + "\n")
            if exploit.payload:
                f.write(f"Tag: {exploit.payload.tag}\n")
                f.write(f"Last Payload: {exploit.payload.value}\n")
            f.write("="*125+"\n\n")

    def verify_flow(self, flow: ObHttpFlow) -> bool:
        def is_placeholder(value: str) -> bool:
            if type(value) is not str:
                return False
            return value in PLACEHOLDER

        def fill_placeholder(trace_id: str,  placeholder: str):
            regex = r"{{(?P<attribute>[a-z0-9_]+)!(?P<index>\d+)}}"
            matches = re.search(regex, placeholder)
            if not matches:
                logging.warning(
                    "can not fill the placeholder, not a valid placeholder")
                return
            index = matches.group("index")
            index = int(index)
            attribute = matches.group("attribute")
            flow: ObHttpFlow = self.DB.get_flow_by_trace_id(trace_id, index)
            if flow is None:
                logging.warning(
                    "can not fill the placeholder, resource not found")
                return
            return getattr(flow, attribute, None)

        attack_vector: AttackVector = self.vector_table[flow.vector_id]
        if attack_vector is None:
            return True
        # ret = False
        index = flow.trace_index
        exploit: Exploit = attack_vector.vector[index]
        verify_functions = exploit.verify_functions
        for func in verify_functions:
            filled_func = copy.deepcopy(func)
            verify = getattr(AsserterServiceAPI, func.function_name, None)
            if not callable(verify):
                logging.warning(
                    f"Verify Function with name {func.function_name} is NOT valid")
                return False
            parameters = inspect.signature(verify).parameters
            real_parameter_set = set(parameters.keys())
            func_parameter_set = set(func.arguments.keys())

            if not func_parameter_set.issubset(func_parameter_set):
                logging.warning(f"Invalid function arguments")
                return False
            diff = real_parameter_set.difference(func_parameter_set)
            # missingParameter = False
            for p in diff:
                parameter = parameters[p]
                if parameter.default == inspect._empty:
                    if p not in BUILDIN:
                        logging.warning(
                            f"Argument {p} in Function {func.function_name} is missing")
                        return False
                    filled_func.arguments[p] = fill_placeholder(
                        flow.trace_id, r"{{"+p+f"!{flow.trace_index}"+r"}}")

            for argName, argValue in func.arguments.items():
                if is_placeholder(argValue):
                    trace_id = flow.trace_id
                    filled = fill_placeholder(trace_id, argValue)
                    if filled is None:
                        return False
                    filled_func.arguments[argName] = fill_placeholder(
                        trace_id, argValue)
            passed = verify(
                **filled_func.arguments) == filled_func.expected_value
            if not passed:
                return False
        return True

    def preAnalyze(self, flow: ObHttpFlow) -> None:
        if flow.in_trace():
            return
        all_parameters = flow.all_parameters
        for param, value in all_parameters.items():
            for vector_id, vector in self.vector_table.items():
                # Skip this vector if there nothing to do
                if vector.number_of_flow <= 1 and vector.vector[0] is None:
                    continue
                input_id = i.calculate_id(
                    param, flow.http_method, flow.request_scheme, flow.request_host, flow.request_path)

                # Save The input if necessary
                if input_id not in self.inputs:
                    new_input = self.DB.insert_input(
                        param=param, example_values=[all_parameters[param]], flow=flow)
                    self.inputs[input_id] = new_input
                else:
                    self.inputs[input_id].example_values.append(
                        all_parameters[param])
                    self.DB.add_example_value(input_id, all_parameters[param])
                # End

                if vector.match(self.inputs[input_id]):
                    # logging.warning(f"{param} match vector {vector.id}")
                    clone = flow.copy()
                    observer = dict()
                    observer['vector-id'] = vector_id
                    observer["target-parameters"] = [param]
                    observer['exploit-number'] = 0 if vector.vector[0] else 1
                    new_trace = InputTrace(
                        vector_id, input_id, vector.bug_type, [flow.id, clone.id])
                    self.DB.insert_trace(new_trace)
                    observer['trace-id'] = new_trace.id
                    clone.observer = observer
                    clone.request_headers['observer'] = clone.serialize_observer(
                    )
                    clone.replay()

    def analyze_response(self, flow: ObHttpFlow):
        if not flow.in_trace():
            return
        passed = self.verify_flow(flow)
        if not passed:
            return

        vector = self.vector_table[flow.vector_id] if flow.vector_id and flow.vector_id in self.vector_table else None

        # This is the last step in this attack vector
        if flow.trace_index + 1 >= vector.number_of_flow:
            trace_id = flow.trace_id
            self.report_bug(trace_id)
            return
        observer = flow.observer
        observer['exploit-number'] = flow.trace_index + 1
        clone = flow.copy()
        clone.request_headers["observer"] = flow.serialize_observer()
        clone.replay()


class PayloadInjector(BaseModule):
    """This class is responsible for injecting payloads into the request."""

    def __init__(self, vector_table: dict[str:AttackVector], db_service) -> None:
        super().__init__(vector_table, db_service)

    def inject_payloads(self, flow: ObHttpFlow, attack_vector: AttackVector) -> list[ObHttpFlow]:
        targetParameters = flow.target_parameters

        def render_payload(origin_value: str, payload_value: str, position: str) -> str:
            ret = None
            if position == "inject":
                ret = origin_value[:int(
                    len(origin_value)/2)] + payload_value + origin_value[int(len(origin_value)/2):]
            elif position == "prepend":
                ret = payload_value + origin_value
            elif position == "append":
                ret = origin_value + payload_value
            elif position == "wrap":
                ret = payload_value.replace(r"{{x}}", origin_value)
            else:
                ret = payload_value
            return ret

        def inject_payload(flow: ObHttpFlow, parameter: str, payload: str) -> None:
            if parameter in flow.all_parameters:
                flow.all_parameters[parameter] = payload

        exploit_index = flow.trace_index
        exploit: Exploit = attack_vector.vector[exploit_index]
        for param in targetParameters:
            payload = exploit.payload
            if payload is None:
                continue
            inject_payload(flow, param, render_payload(
                flow.all_parameters[param], payload.value, payload.position))

    def handle_request(self, flow: ObHttpFlow) -> None:
        """This method is responsible for injecting payloads into the request."""
        if not flow.in_trace():
            return
        attack_vector = self.vector_table[flow.vector_id]
        if attack_vector is None:
            return
        self.inject_payloads(flow, attack_vector)

    def handle_response(cls, flow: ObHttpFlow) -> None:
        pass


class Observer:
    def __init__(self) -> None:
        # Collect all attack templates
        vector_table: dict[str:AttackVector] = dict()
        for path in glob.glob(pathname=os.path.join(ROOT_DIR, 'core', 'templater', 'recipe', '**', '*.yaml'), recursive=True):
            newTemplate = parse_template(path)
            if newTemplate is None:
                continue
            for vector in newTemplate.vectors:
                vector_table[vector.id] = vector
        self.vector_table = vector_table
        db_service = DataAccessLayer()
        self.INJECTOR = PayloadInjector(vector_table, db_service)
        self.ANALYZER = BugAnalyzer(vector_table, db_service)
        self.flows: dict[str:ObHttpFlow] = dict()
        self.DB = db_service

    def handle_request(self, flow: ObHttpFlow):
        self.ANALYZER.preAnalyze(flow)
        self.INJECTOR.handle_request(flow)

    def handle_response(self, flow: ObHttpFlow):
        self.DB.insert_flow(flow)
        self.ANALYZER.analyze_response(flow)
        # self.INJECTOR.handle_response(flow)
