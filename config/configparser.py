# import logging
import os
import yaml
from customenum.bugtype import BugType
from customenum.payloadmode import PayloadMode
from customenum.attackmode import AttackMode
from persistence.dal import DataAccessLayer
current = os.path.dirname(os.path.realpath(__file__))


class ConfigParser:
    DB_SERVICE_API = DataAccessLayer()
    FILE_PATH = os.path.join(current, 'config.yaml')

    @classmethod
    def __read_config_file(cls, filePath: str):
        hit = False
        modified_time = os.path.getmtime(filePath)
        saved_file = cls.DB_SERVICE_API.get_pickle_file_by_path(filePath)
        if saved_file:
            hit = saved_file.last_modified == modified_time
        if not hit:
            with open(filePath, 'r') as stream:
                data_loaded = yaml.safe_load(stream)
                if saved_file is None:
                    cls.DB_SERVICE_API.insert_pickle_file(
                        filePath, data_loaded, modified_time)
                else:
                    cls.DB_SERVICE_API.update_pickle_file(
                        filePath, data_loaded, modified_time)
                return data_loaded
        else:
            return saved_file.data

    @classmethod
    def get_attack_mode(cls, bugType: BugType) -> AttackMode:
        data_loaded = cls.__read_config_file(cls.FILE_PATH)
        mode = data_loaded['bug-type'][bugType.value]['attack-mode']
        mode = str(mode).upper()
        names = [member.name for member in AttackMode]
        if mode not in names:
            return AttackMode.UNKNOWN
        return AttackMode[mode]

    @classmethod
    def get_payload_mode(cls, bugType: BugType) -> PayloadMode:
        data_loaded = cls.__read_config_file(cls.FILE_PATH)
        mode = data_loaded['bug-type'][bugType.value]['payload-mode']
        mode = str(mode).upper()
        names = [member.name for member in PayloadMode]
        if mode not in names:
            return PayloadMode.UNKNOWN
        return PayloadMode[mode]

    @classmethod
    def get_target_parameters(cls, bugType: BugType) -> set[str] or None:
        data_loaded = cls.__read_config_file(cls.FILE_PATH)
        return set(data_loaded['bug-type'][bugType.value]['target-parameters'])

    @classmethod
    def __check_config_syntax(cls) -> bool:
        return True
