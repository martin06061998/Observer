
import copy
import inspect
import logging
from multiprocessing import Lock
import re
from utilities.util import md5
from persistence.models.param import Parameter
from persistence.models.flow import ObHttpFlow
from definitions import ATTRIBUTE_TABLE
from core.analyzer.asserter.assertserviceapi import AsserterServiceAPI
from utilities.util import base64_decode
from services.network import request





class Payload:
    def __init__(self, value: str, tag: str = "None", position: str = "None"):
        self.value = value
        self.tag = tag.lower()
        self.position = position.lower()
        self.id = md5(value+tag+position)

    def render(self, pattern: str) -> str:
        position = self.position
        payload_value = self.value
        ret = None
        if position == "inject":
            ret = pattern[:int(
                len(pattern)/2)] + payload_value + pattern[int(len(pattern)/2):]
        elif position == "prepend":
            ret = payload_value + pattern
        elif position == "append":
            ret = pattern + payload_value
        elif position == "wrap":
            ret = payload_value.replace(r"{{x}}", pattern)
        else:
            ret = payload_value
        return ret


class VerifyFunction:
    def __init__(self, function_name: str, arguments: dict, expected_value: bool) -> None:
        self.function_name = function_name.lower()
        self.arguments = arguments
        self.expected_value = expected_value


class Exploit():
    def __init__(self, verify_functions: list[VerifyFunction], payload: Payload = None, match_condition: str = "all") -> None:
        self.verify_functions = verify_functions
        self.match_condition = match_condition
        self.tag = None
        self.payload = payload
        if payload:
            self.tag = payload.tag.lower().strip()

class ParameterMatcher():
    def __init__(self, type: str, part: str, target: str, words: list[str] = None, regexes: list[str] = None) -> None:
        self.type = type
        self.part = part
        self.target = target
        self.words = None
        self.regexes = None
        if words:
            self.words = set(words)
        elif regexes:
            self.regexes = set(regexes)

    def match(self, p: Parameter) -> bool:
        if self.part != p.part and self.part != "all":
            return False
        target = None
        if self.target == "name":
            target = p.name
        else:
            target = p.example_values[-1]
        if self.words:
            return target in self.words
        elif self.regexes:
            for regex in self.regexes:
                try:
                    if (type(target) is bytes or type(target) is str) and re.match(regex, target, re.IGNORECASE):
                        return True
                except Exception as e:
                    logging.warning(f"error when handle {regex} {str(e)}")
        return False


class AttackVector():

    def __init__(self, id: str, path: str, matchers: list[ParameterMatcher], exploit_sequence: list[Exploit], bug_type: str,description:str=None) -> None:
        self.exploit_sequence = exploit_sequence
        self.bug_type = bug_type
        self.id = id
        self.matchers = matchers
        self.tried_parameters = set()
        self.path = path
        self.description = description

    def match(self, p: Parameter):
        for matcher in self.matchers:
            if matcher.match(p):
                return True
        return False

    def verify(self, flow_sequence: list[ObHttpFlow]) -> bool:
        """ Verify if this flow pass all defined conditions in the yaml file

        Args:
            flow (ObHttpFlow): the flow target

        Returns:
            bool: True if passed
        """

        def fill_value(value: str):
            regex = r"{{(?P<attribute>[a-z0-9_]+)!(?P<index>\d+)}}"
            matches = re.search(regex, str(value))
            if not matches:
                return value
            index = matches.group("index")
            index = int(index)
            attribute = matches.group("attribute")
            if index >= len(flow_sequence) or index < 0:
                logging.error(
                    f"index {index} is out of range in the required flow sequence for verification, {self.path}")
                return value
            flow: ObHttpFlow = flow_sequence[index]
            mapped_attribute = ATTRIBUTE_TABLE[attribute]
            if mapped_attribute in flow.__dict__:
                return flow.__dict__[mapped_attribute]
            return value

        for index, exploit in enumerate(self.exploit_sequence):
            if exploit is None:
                continue

            verify_functions = exploit.verify_functions


            for func in verify_functions:
                # This object will store all needed information to run
                filled_func = copy.deepcopy(func)

                verify = getattr(AsserterServiceAPI, func.function_name, None)

                # START FUNCTION NAME CHECKING
                if not callable(verify):
                    logging.error(
                        f"Verify function with name {func.function_name} is NOT valid, template {self.path}")
                    return False
                # END

                # START PARAMETER CHECKING
                # Check if all required parameters exist and have valid values
                required_parameters = inspect.signature(verify).parameters
                for name, value in required_parameters.items():
                    if name not in func.arguments.keys() and value.default == inspect._empty:
                        if name not in ATTRIBUTE_TABLE:
                            logging.error(
                                f"param {name} is required, template {self.path}\n")
                            return False
                        mapped_attr = ATTRIBUTE_TABLE[name]
                        if index >= len(flow_sequence):
                            logging.error(
                                f"index {index} is out of range in the required flow sequence for verification, template {self.path}\n")
                            return False
                        if mapped_attr not in flow_sequence[index].__dict__:
                            logging.error(
                                f"attribute {name} is not valid, template {self.path}\n")
                            return False
                        filled_func.arguments[name] = flow_sequence[index].__dict__[
                            mapped_attr]

                # Check if parameters are malformed
                for name, value in func.arguments.items():
                    if name not in required_parameters.keys():
                        logging.error(
                            f"param {name} is malformed, template {self.path}")
                        return False
                # END

                # FILL ALL REQUIRED PARAMETERS
                for name, value in func.arguments.items():
                    filled_func.arguments[name] = fill_value(value)
                # END

                passed = verify(
                    **filled_func.arguments) == filled_func.expected_value
                if not passed:
                    return False
        return True
    
    def exploit(self,template_flow:ObHttpFlow,parameter:Parameter,lock:Lock):
        def report_bug():
            with open("bug.log", "a+") as f:
                f.write(f"Bug type: {self.bug_type}\n")
                f.write(f"Description: {self.description}\n")
                f.write(f"Template Path: {self.path}\n")
                f.write(f"Parameter: {parameter.name}\n")
                f.write(f"Flow id: {template_flow.id}\n")
                payload = None
                for e in self.exploit_sequence:
                    if e and e.payload:
                        payload = e.payload
                        break
                     
                if payload:
                    f.write(f"Payload: {payload.render(pattern)}\n")
                    f.write(f"Tag: {payload.tag}\n")
                f.write(f"="*125+"\n\n")
                f.flush()
    
    
        #START
        if not self.match(parameter):
            return
        end_point = f"{template_flow.request_scheme}://{template_flow.request_host}{template_flow.request_path}"
        headers: dict = template_flow._request_headers

        headers["tag"] = self.bug_type
        headers.pop("content-length",None)
        flow_sequence = [template_flow]
        method = parameter.http_method
        params = None
        data=None
        pattern = None

        if parameter.part == "query":
            params = copy.deepcopy(template_flow._query)
            pattern = copy.deepcopy(params[parameter.name])
        else:
            data = copy.deepcopy(template_flow._request_body_parameters)
            pattern = copy.deepcopy(data[parameter.name])

        exploit:Exploit
        for exploit in self.exploit_sequence:
            if exploit is None:
                continue
            payload:Payload = exploit.payload
            rendered_payload = payload.render(pattern)
            if params:
                params[parameter.name] = rendered_payload
            if data:
                data[parameter.name] = rendered_payload
            javascript_enable = True if self.bug_type == "xss" else False

            
            ret : dict = request(method=method,end_point=end_point,headers=headers,params=params,data=data,timeout=120,javascript_enable=javascript_enable,proxy="http://127.0.0.1:8080")
       
            if ret.get("msg",None) != "ok":
                logging.warning(f"An error occur in AttackVector.exploit: {ret.get('msg',None)}")
                continue 
            ret["content"] =  base64_decode(ret["content"])
            new_flow = ObHttpFlow(request_scheme=template_flow.request_scheme, request_host=template_flow.request_host, request_path=template_flow.request_path, http_method=template_flow.http_method, url=template_flow.url,
                                        status_code=ret.get("status_code"), timestamp=ret.get("elapsed"), request_headers=headers, response_headers=ret.get("response_headers"), response_body_content=ret.get("content"), query=params)
            flow_sequence.append(new_flow)


        # VULNERABILITY ASSESSMENT
        isVulnerable = self.verify(flow_sequence=flow_sequence)

        # REPORT BUG
        if isVulnerable:
            with lock:
                report_bug()
            
        # END

class Template():

    def __init__(self, path: str, bug_type: str, vectors: list[AttackVector] = None, bug_name: str = "") -> None:
        self.bug_type = bug_type.lower()
        self.vectors = []
        if vectors is not None:
            self._vectors = vectors
        self.bug_name = bug_name.lower()
        self.path = path
        self.id = md5(path)