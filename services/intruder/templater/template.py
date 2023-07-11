
import itertools
import logging
from persistence.models.attackvector import Exploit, ParameterMatcher
import yaml
from persistence.models.attackvector import AttackVector, Payload, VerifyFunction
from utilities.util import md5
import glob
import aiofiles as aiof
import os
import asyncio
from definitions import ROOT_DIR

async def parse_template(path: str) -> list[AttackVector]:
    def parse_matchers(yml_template:dict):
        yml_target_parameters = yml_template['target-arguments']
        new_matchers = []
        for yml_parameter in yml_target_parameters:
            yml_type = yml_parameter['type']
            yml_part = yml_parameter['part']
            yml_target = yml_parameter['target']
            new_matcher = None
            if yml_type == "word":
                yml_words = yml_parameter['words']
                new_matcher = ParameterMatcher(
                    yml_type, yml_part, yml_target, words=yml_words)
            elif yml_type == "regex":
                yml_regexes = yml_parameter['regexes']
                new_matcher = ParameterMatcher(
                    yml_type, yml_part, yml_target, regexes=yml_regexes)
            new_matchers.append(new_matcher)
        return new_matchers
    
    def parse_verify_functions(yml_flow:dict):
        new_verify_functions: list[VerifyFunction] = []
        yml_verify_functions = yml_flow['verify']
        for yml_verify_function in yml_verify_functions:
            yml_function_name = yml_verify_function['function']
            if "args" in yml_verify_function:
                yml_arguments = yml_verify_function['args']
            else:
                yml_arguments = dict()
            if 'expected-value' in yml_verify_function and type(yml_verify_function['expected-value']) is bool:
                yml_expected_value = yml_verify_function['expected-value']
            else:
                yml_expected_value = True
            new_verify_function = VerifyFunction(
                yml_function_name, yml_arguments, yml_expected_value)
            new_verify_functions.append(new_verify_function)
        return new_verify_functions
        
    def parse_exploits(yml_flow:dict):
        current_exploit_list : list[Exploit] = None 
        if 'payloads' in yml_flow:
            current_exploit_list = []
            yml_payloads = yml_flow['payloads']
            for yml_payload in yml_payloads:
                yml_value = yml_payload['value']
                yml_position = yml_payload['position']
                yml_tag = str(yml_payload['tag'])
                new_payload = Payload(yml_value, yml_tag, yml_position)
                new_exploit = Exploit(
                    verify_functions=new_verify_functions, payload=new_payload)
                current_exploit_list.append(new_exploit)
        
        return current_exploit_list
    
    try:
        async with aiof.open(path, 'r') as f:
            # START PARSING TEMPLATE
            vectors = [] # RETURN VALUE
            yml_template = yaml.safe_load(await f.read())
            yml_bug_type = yml_template['bug-type']
            yml_number_of_flow = yml_template['number-of-flow']
            yml_flows = yml_template['flows']
            yml_description = yml_template.get("description",None)
            yml_technique = yml_template.get("technique","active")


            # PARSING MATCHER
            new_matchers =  parse_matchers(yml_template=yml_template)
            # END
            
            # START PARSING FLOWS
            exploits = []
            for i in range(yml_number_of_flow):
                yml_flow_name = f"flow_{i}"
                current_exploit_list: list[Exploit] = []
                if yml_flow_name not in yml_flows:
                    if i == 0:
                        default_exploit_list = [Exploit([],Payload("","default","append"))] 
                        exploits.append(default_exploit_list)
                        continue
                    else:
                        return
                yml_flow = yml_flows[yml_flow_name]
                
                # PARSING VERIFY FUNCTION
                new_verify_functions =  parse_verify_functions(yml_flow=yml_flow)
                # END

                # START PARSING PAYLOADS
                current_exploit_list =  parse_exploits(yml_flow=yml_flow)
                if current_exploit_list is None:
                    current_exploit_list = [None]
                exploits.append(current_exploit_list)
            # END
            
            # BUILD VECTOR
            i=0
            for exploit_sequence in itertools.product(*exploits):
                new_vector = AttackVector(id=md5(str(i)+path),path=path,matchers=new_matchers,exploit_sequence=exploit_sequence,bug_type=yml_bug_type,description=yml_description,technique=yml_technique)
                vectors.append(new_vector)
                i=i+1 
            # END

                    
    # END PARSING TEMPLATE
    except Exception as e:
        logging.warning("An error has occur when create template: " + path)
        logging.warning("Message: " + str(e))
        return
    return vectors

async def build_vector_table(vector_list:list[AttackVector]):
    while True:
        vector_list.clear()
        for path in glob.glob(pathname=os.path.join(ROOT_DIR, 'services', 'intruder',  'templater', 'recipe', '**', '*.yaml'), recursive=True):
            vectors =  await parse_template(path)
            if vectors is None:
                continue
            vector_list.extend(vectors)
        await asyncio.sleep(180)