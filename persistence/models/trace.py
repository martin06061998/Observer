

from sqlalchemy import JSON, Boolean, Column, ForeignKey, Integer, String
from persistence.database import Base


class ParameterTrace(Base):
    """A taint trace represents a trace of a taint to a specific vulnerability."""
    __tablename__ = 'traces'
    id = Column(Integer, primary_key=True, autoincrement="auto")
    vector_id = Column(String(50))
    parameter_id = Column(String(50), ForeignKey('parameters.id'))
    bug_type = Column(String(50))
    is_vulnerable = Column(Boolean)
    flow_ids = Column(JSON, nullable=False)

    def __init__(self, vector_id: str, parameter_id: str, bug_type: str, flow_ids: list[str] = [], is_vulnerable: bool = False):
        self.vector_id = vector_id
        self.parameter_id = parameter_id
        self.is_vulnerable = is_vulnerable
        self.bug_type = bug_type
        self.flow_ids = flow_ids

    @property
    def current_exploit_index(self):
        return len(self.flow_ids) - 1
