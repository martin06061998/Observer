


import time
from persistence.database import Database
from persistence.models.input import Input
from persistence.models.trace import InputTrace
from persistence.models.flow import ObHttpFlow


class TraceDAO():
    """This class is responsible for connecting to the database and executing queries"""

    def __init__(self) -> None:
        pass


    def insert_trace(self, new_trace: InputTrace):
        session = Database.get_session()
        saved_input = session.query(Input).get({"id": new_trace.input_id})
        saved_input.total_of_trace += 1
        session.add(new_trace)
        session.commit()
        session.refresh(new_trace)
        session.close()
        return new_trace

    def insert_flow_id_to_trace(self, trace_id: str, flow_id: str):
        session = Database.get_session()
        MAX_TRY = 5
        saved_trace = None
        while saved_trace is None and MAX_TRY > 0:
            saved_trace = session.query(InputTrace).get({"id": trace_id})
            MAX_TRY -= 1
            if saved_trace is None:
                time.sleep(0.1)
        if saved_trace:
            saved_trace.flow_ids.append(flow_id)
        session.commit()
        session.close()

    def get_trace_by_id(self, id: int):
        session = Database.get_session()
        trace = session.query(InputTrace).get({"id": id})
        session.close()
        return trace

    def get_flow_by_trace_id(self, trace_id: str, index: int):
        session = Database.get_session()
        trace = session.query(InputTrace).get({"id": trace_id})
        if trace is None:
            return
        if index >= len(trace.flow_ids):
            return
        flow_id = trace.flow_ids[index]
        saved_flow = session.query(ObHttpFlow).get({"id": flow_id})
        session.close()
        return saved_flow
