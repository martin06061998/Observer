
from persistence.database import Database
from persistence.models.input import Input as i
from persistence.models.flow import ObHttpFlow


class InputDao:
    def __init__(self) -> None:
        pass

    def insert_input(self, new_input: i = None, param: str = None, example_values: list[str] = None, flow: ObHttpFlow = None):
        session = Database.get_session()
        if new_input is None:
            new_input = i.new_input(param, example_values, flow)
        session.add(new_input)
        session.commit()
        session.refresh(new_input)
        session.close()
        return new_input

    def get_input_by_id(self, id: str):
        session = Database.get_session()
        saved_input = session.query(i).get({"id": id})
        session.close()
        return saved_input
    
    def add_example_value(self,id:str,value:str):
        session = Database.get_session()
        saved_input : i = session.query(i).get({"id": id})
        if saved_input:
            saved_input.example_values.append(value)
        session.commit()
        session.refresh(saved_input)
        session.close()
        return saved_input
