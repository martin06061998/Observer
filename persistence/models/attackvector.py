
import re
from utilities.util import md5
from persistence.models.input import Input as i


class Payload:
    @classmethod
    def is_valid_position(cls, value: str) -> bool:
        if value is None or type(value) is not str:
            return False
        ACCEPT_VALUE = {"append", "prepend", "inject", "wrap"}
        return value in ACCEPT_VALUE

    @classmethod
    def is_valid_tag(cls, tag: str) -> bool:
        return type(tag) is str

    @classmethod
    def is_valid_value(cls, value: str) -> bool:
        return value is not None and type(value) is str

    def __init__(self, value: str, tag: str = "None", position: str = "None"):
        if not Payload.is_valid_position(position):
            raise ValueError('position value is not valid')
        if not Payload.is_valid_tag(tag):
            raise ValueError('tag value is not valid')
        if not Payload.is_valid_value(value):
            raise ValueError('payload value is not valid')
        self._value = value.lower()
        self._tag = tag.lower()
        self._position = position.lower()
        self._id = md5(value+tag+position)

    @property
    def id(self):
        self._id

    @property
    def position(self):
        return self._position

    @position.setter
    def position(self, position: str):
        if not Payload.is_valid_position(position):
            raise ValueError('position value is not valid')
        self._position = position

    @property
    def tag(self):
        return self._tag

    @tag.setter
    def tag(self, tag: str):
        if not Payload.is_valid_tag(tag):
            raise ValueError('tag value is not valid')
        self._tag = tag.lower()

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value: str):
        if not Payload.is_valid_value(value):
            raise ValueError('payload value is not valid')
        self._value = value.lower()


class VerifyFunction:
    @classmethod
    def is_valid_function(cls, function_name: str) -> bool:
        if function_name is None or type(function_name) is not str:
            return False
        return True

    @classmethod
    def is_valid_args(cls, arguments: dict) -> bool:
        return arguments is None or type(arguments) is dict

    def __init__(self, function_name: str, arguments: dict, expected_value: bool) -> None:
        if not VerifyFunction.is_valid_function(function_name):
            raise ValueError('function value is not valid')
        if not VerifyFunction.is_valid_args(arguments):
            raise ValueError('arguments values are not valid')
        self._function_name = function_name.lower()
        self._arguments = arguments
        self._expected_value = expected_value

    @property
    def function_name(self):
        return self._function_name

    @function_name.setter
    def function_name(self, function_name: str):
        if not VerifyFunction.is_valid_function(function_name):
            raise ValueError('function name is not valid')
        self._function_name = function_name.lower()

    @property
    def arguments(self):
        return self._arguments

    @arguments.setter
    def arguments(self, arguments: dict):
        if not VerifyFunction.is_valid_args(arguments):
            raise ValueError('arguments values are not valid')
        self._arguments = arguments

    @property
    def expected_value(self):
        return self._expected_value


class Exploit():
    @classmethod
    def is_valid_match_condition(cls, condition: str) -> str:
        if condition is None or type(condition) is not str:
            return False
        ACCEPT_VALUE = {"all", "any"}
        return condition in ACCEPT_VALUE

    def __init__(self, verify_functions: list[VerifyFunction], payload: Payload = None, match_condition: str = "all") -> None:
        if match_condition and not Exploit.is_valid_match_condition(match_condition):
            raise ValueError('match condition is not valid')
        self._verify_functions = verify_functions
        self._match_condition = match_condition
        self._tag_set = set()
        self._payload = payload
        if payload:
            tag_fragments = payload.tag.split(",")
            for tag in tag_fragments:
                self._tag_set.add(tag.lower().strip())

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, payload: Payload):
        self._payload = payload

    @property
    def verify_functions(self):
        return self._verify_functions

    @verify_functions.setter
    def verify_functions(self, verify_functions: list[VerifyFunction]):
        self._verify_functions = verify_functions

    @property
    def match_condition(self):
        return self._match_condition

    @property
    def tag_set(self) -> set[str]:
        return self._tag_set


class ParameterMatcher():
    def __init__(self, type: str, part: str, target: str, words: list[str] = None, regexes: list[str] = None) -> None:
        self._type = type
        self._part = part
        self._target = target
        self.words = None
        self.regexes = None
        if words:
            self.words = set(words)
        elif regexes:
            self.regexes = set(regexes)

    def match(self, p: i) -> bool:
        target = None
        if self._target == "name":
            target = p.name
        else:
            target = p.example_values[-1]
        if target is None:
            target = ""
        if self.words:
            return target in self.words
        elif self.regexes:
            for regex in self.regexes:
                try:
                    if re.match(regex, target, re.IGNORECASE):
                        return True
                except:
                    pass
        return False


class AttackVector():

    def __init__(self, id: str, machers: list[ParameterMatcher], vector: list[Exploit] = None, bug_type="") -> None:
        self._vector = vector
        self._bug_type = bug_type
        self._id = id
        self._matchers = machers

    def match(self, p: i):
        for matcher in self._matchers:
            if (matcher._part == p.part or matcher._part == "all") and matcher.match(p):
                return True
        return False

    @property
    def vector(self):
        return self._vector

    @vector.setter
    def vector(self, vector: list[Exploit]):
        self._vector = vector

    @property
    def number_of_flow(self):
        return len(self._vector)

    @property
    def bug_type(self):
        return self._bug_type

    @bug_type.setter
    def bug_type(self, bug_type: str):
        self._bug_type = bug_type

    @property
    def id(self):
        return self._id


class Template():
    @classmethod
    def is_valid_bug_type(cls, bug_type: str) -> bool:
        if bug_type is None or type(bug_type) is not str:
            return False
        ACCEPT_VALUE = {"sqli", "xss", "rce", "open_redirect"}
        return bug_type in ACCEPT_VALUE

    @classmethod
    def is_valid_bug_name(cls, bug_name: str) -> bool:
        return bug_name is None or type(bug_name) is str

    def __init__(self, path: str, bug_type: str, vectors: list[AttackVector] = None, bug_name: str = "") -> None:
        if not Template.is_valid_bug_type(bug_type):
            raise ValueError('bug type is not valid')
        if not Template.is_valid_bug_name(bug_name):
            raise ValueError('bug name is not valid')
        self._bug_type = bug_type.lower()
        self._vectors = []
        if vectors is not None:
            self._vectors = vectors
        self._bug_name = bug_name.lower()
        self._path = path
        self._id = md5(path)

    @property
    def bug_name(self):
        return self._bug_name

    @bug_name.setter
    def bug_name(self, bug_name: str):
        if not Template.is_valid_bug_type(bug_name):
            raise ValueError('bug name is not valid')
        self._bug_name = bug_name.lower()

    @property
    def bug_type(self):
        return self._bug_type

    @bug_type.setter
    def bug_type(self, bug_type: str):
        if not Template.is_valid_bug_type:
            raise ValueError('bug type is not valid')
        self._bug_type = bug_type

    @property
    def vectors(self):
        return self._vectors

    @vectors.setter
    def vectors(self, vectors: list[AttackVector]):
        self._vectors = vectors

    @property
    def path(self):
        return self._path

    @property
    def id(self):
        return self._id
