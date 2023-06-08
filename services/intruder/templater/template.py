
import itertools
import logging
from persistence.models.attackvector import Exploit, Template, ParameterMatcher
import yaml
from persistence.models.attackvector import AttackVector, Payload, VerifyFunction
from utilities.util import md5
import glob
from aiofile import async_open
import os
import asyncio
from definitions import ROOT_DIR

async def parse_template(path: str) -> Template:
    try:
        async with async_open(path, 'r') as f:
            # START PARSING TEMPLATE
            yml_template = yaml.safe_load(await f.read())
            yml_bug_type = yml_template['bug-type']
            yml_number_of_flow = yml_template['number-of-flow']
            yml_flows = yml_template['flows']
            new_template = Template(path=path, bug_type=yml_bug_type)
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
            if yml_number_of_flow < 1 or yml_number_of_flow > 5:
                return
            exploit_list: list[set[Exploit]] = [None] * yml_number_of_flow
            tagged_exploit_dict: dict[str:set[Exploit]] = dict()

        # START PARSING FLOWS
            for i in range(yml_number_of_flow):
                yml_flow_name = f"flow_{i}"
                if yml_flow_name not in yml_flows:
                    if i == 0:
                        continue
                    else:
                        return
                yml_flow = yml_flows[yml_flow_name]

                # Start parsing verify functions
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
                # End parsing verify functions

            # START PARSING PAYLOADS
                if 'payloads' in yml_flow:
                    yml_payloads = yml_flow['payloads']
                    for yml_payload in yml_payloads:
                        yml_value = yml_payload['value']
                        yml_position = yml_payload['position']
                        yml_tag = str(yml_payload['tag'])
                        new_payload = Payload(yml_value, yml_tag, yml_position)
                        new_exploit = Exploit(
                            verify_functions=new_verify_functions, payload=new_payload)
                        for tag in new_exploit.tag_set:
                            if tag not in tagged_exploit_dict:
                                tagged_exploit_dict[tag] = {new_exploit}
                            else:
                                tagged_exploit_dict[tag].add(new_exploit)

                        if exploit_list[i] is None:
                            exploit_list[i] = {new_exploit}
                        else:
                            exploit_list[i].add(new_exploit)
                else:
                    new_exploit = Exploit(
                        verify_functions=new_verify_functions)
                    exploit_list[i] = {new_exploit}
                    tagged_exploit_dict[yml_bug_type] = {new_exploit}
            # END PARSING PAYLOADS

        # END PARSING FLOWS
            i = 0
            for _, tagged_exploit_set in tagged_exploit_dict.items():
                list_of_intersection = []
                for exploit_set in exploit_list:
                    if exploit_set is None:
                        continue
                    list_of_intersection.append(exploit_set.intersection(
                        tagged_exploit_set))
                for element in itertools.product(*list_of_intersection):
                    new_attack_vector = AttackVector(id=md5(
                        new_template.id+str(i)), exploit_sequence=None, path=path, matchers=new_matchers, bug_type=yml_bug_type)
                    if exploit_list[0] is not None:
                        new_attack_vector.exploit_sequence = element
                    else:
                        new_attack_vector.exploit_sequence = ((None,)+element)
                    new_template.vectors.append(new_attack_vector)
                    i = i + 1
    # END PARSING TEMPLATE
    except Exception as e:
        logging.warning("An error has occur when create template: " + path)
        logging.warning("Message: " + str(e))
        return
    return new_template

async def build_vector_table(vector_list:list[AttackVector]):
    while True:
        vector_list.clear()
        for path in glob.glob(pathname=os.path.join(ROOT_DIR, 'services', 'intruder',  'templater', 'recipe', '**', '*.yaml'), recursive=True):
            newTemplate = await parse_template(path)
            if newTemplate is None:
                continue
            vector_list.extend(newTemplate.vectors)
        await asyncio.sleep(180)