
import copy
import inspect
import logging
import re
from utilities.util import md5
from persistence.models.param import Parameter
from persistence.models.flow import ObHttpFlow
from definitions import ATTRIBUTE_TABLE
from core.analyzer.asserter.assertserviceapi import AsserterServiceAPI
import asyncio
import aiofiles as aiof
import httpx
from utilities.util import base64_decode

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

            if verify_functions is None or len(verify_functions) < 1:
                return True

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
    
    async def exploit(self,flow:ObHttpFlow,parameter:Parameter):
        async def report_bug():
            async with aiof.open("bug.log", "a+") as f:
                await f.write(f"Bug type: {self.bug_type}\n")
                await f.write(f"Description: {self.description}\n")
                await f.write(f"Template Path: {self.path}\n")
                await f.write(f"Parameter: {parameter.name}\n")
                await f.write(f"Flow id: {flow.id}\n")
                exploit = self.exploit_sequence[0] if self.exploit_sequence[0] else self.exploit_sequence[1] 
                payload = exploit.payload if exploit.payload  else None
                if payload:
                    await f.write(f"Payload: {payload.render(pattern)}\n")
                    await f.write(f"Tag: {payload.tag}\n")
                await f.write(f"="*125+"\n\n")
                await f.flush()
    
    
        #START
        await asyncio.sleep(0.2)

        if not self.match(parameter):
            return
        end_point = f"{flow.request_scheme}://{flow.request_host}{flow.request_path}"
        headers: dict = flow._request_headers

        headers["tag"] = self.bug_type
        headers.pop("content-length",None)
        headers.pop("Content-Length",None)
        flow_sequence = [flow]
        method = parameter.http_method
        params = None
        data=None
        pattern = None

        if parameter.part == "query":
            params = copy.deepcopy(flow._query)
            pattern = copy.deepcopy(params[parameter.name])
        else:
            data = copy.deepcopy(flow._request_body_parameters)
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
            
            ret:dict=None
            browser = True if self.bug_type == "xss" else False
            
            async with httpx.AsyncClient() as client:
                r : httpx.Response = await client.post(url="http://127.0.0.1:5554/request",json={
                "method":method,
                "end_point":end_point,
                "headers":headers,
                "data":data,
                "params":params,
                "browser":browser
            },timeout=120)

            ret = r.json()

            if ret.get("msg",None) != "ok":
                logging.warning(f"An error has occurred: {ret.get('msg',None)}")
                continue 
            ret["content"] =  base64_decode(ret["content"])
            new_flow = ObHttpFlow(request_scheme=flow.request_scheme, request_host=flow.request_host, request_path=flow.request_path, http_method=flow.http_method, url=flow.url,
                                        status_code=ret.get("status_code"), timestamp=ret.get("elapsed"), request_headers=headers, response_headers=ret.get("response_headers"), response_body_content=ret.get("content"), query=params)
            flow_sequence.append(new_flow)


        # VULNERABILITY ASSESSMENT
        isVulnerable = self.verify(flow_sequence=flow_sequence)

        # REPORT BUG
        if isVulnerable:
            await report_bug()
            
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
