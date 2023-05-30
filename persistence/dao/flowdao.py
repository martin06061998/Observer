
from sqlalchemy import exc
from persistence.database import Database
from persistence.models.file import PickleFile
from persistence.models.flow import ObHttpFlow


class FlowDAO():
    """This class is responsible for connecting to the database and executing queries"""

    def __init__(self) -> None:
        pass


    def get_flow_by_id(self, id: str) -> ObHttpFlow:
        session = Database.get_session()
        flow = session.query(ObHttpFlow).get({"id": id})
        session.close()
        return flow

    def insert_flow(self, flow: ObHttpFlow):
        if flow.response_body_content is None:
            return
        session = Database.get_session()
        try:
            session.add(flow)
            session.commit()
            session.refresh(flow)
        except exc.IntegrityError:
            session.rollback()
        finally:
            session.close()

    def insert_pickle_file(self, path: str, data, last_modified: float):
        session = Database.get_session()
        newFile = PickleFile(path, data, last_modified)
        session.add(newFile)
        session.commit()
        session.close()
        return newFile

    def update_pickle_file(self, path: str, data, last_modified: float):
        session = Database.get_session()
        file = session.query(PickleFile).filter(
            PickleFile.path == path).first()
        file.data = data
        file.last_modified = last_modified
        session.commit()
        session.close()
        return file

    def get_pickle_file_by_path(self, path) -> PickleFile:
        session = Database.get_session()
        ret = session.query(PickleFile).filter(PickleFile.path == path).first()
        session.close()
        return ret
