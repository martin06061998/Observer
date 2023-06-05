
from sqlalchemy import desc, exc, select
from persistence.database import db_session
from persistence.models.flow import ObHttpFlow
from persistence.models.param import ParamFlowMap


class FlowDAO():
    """This class is responsible for connecting to the database and executing queries"""

    def __init__(self) -> None:
        pass

    async def get_flow_by_id(self, id: str) -> ObHttpFlow:
        async_session = await db_session()
        async with async_session() as session:
            async with session.begin():
                stmt = select(ObHttpFlow).where(ObHttpFlow.id == id)
                result = await session.execute(stmt)
                saved_flow = result.scalars().one()
        return saved_flow

    async def insert_flow(self, flow: ObHttpFlow):
        async_session = await db_session()
        async with async_session() as session:
            async with session.begin():
                session.add(flow)
            await session.commit()

    async def get_last_flow_by_parameter_id(self, parameter_id: str):
        async_session = await db_session()
        saved_flow = None
        async with async_session() as session:
            async with session.begin():
                stmt = select(ParamFlowMap.flow_id).where(
                    ParamFlowMap.parameter_id == parameter_id).order_by(desc(ParamFlowMap.id)).limit(1)
                result = await session.execute(stmt)
                flow_id = result.scalars().one()
                if flow_id:
                    stmt = select(ObHttpFlow).where(ObHttpFlow.id == flow_id)
                    result = await session.execute(stmt)
                    saved_flow = result.scalars().one()
        return saved_flow
