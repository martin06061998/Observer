
import asyncio
from sqlalchemy import desc, exc, select
from persistence.database import db_session,add_or_do_nothing
from persistence.models.flow import ObHttpFlow
from persistence.models.param import ParamFlowMap
from sqlalchemy import exc

class FlowDAO():
    """This class is responsible for connecting to the database and executing queries"""
    MAX_TRY = 2

    def __init__(self) -> None:
        pass

    async def get_flow_by_id(self, id: str) -> ObHttpFlow:
        
        async_session = await db_session()
        num_of_tried = 0
        saved_flow = None
        while num_of_tried < self.MAX_TRY:
            error = False
            try:
                async with async_session() as session:
                    async with session.begin():
                        stmt = select(ObHttpFlow).where(ObHttpFlow.id == id)
                        result = await session.execute(stmt)
                        saved_flow = result.scalars().one_or_none()
                        error = False
            except exc.SQLAlchemyError as e:
                if num_of_tried == self.MAX_TRY:
                    raise e
                error = True
            if not error:
                break
            num_of_tried = num_of_tried + 1
            await asyncio.sleep(num_of_tried*1)
       
        return saved_flow

    async def insert_flow(self, flow: ObHttpFlow):
        await add_or_do_nothing(flow)
        return flow
    
    
    async def get_last_param_flow(self,group_id:str)->ParamFlowMap:
        async_session = await db_session()
        ret = None
        saved_flow = None
        async with async_session() as session:
            async with session.begin():
                stmt = select(ObHttpFlow).filter(ObHttpFlow.id == ParamFlowMap.flow_id).filter(ParamFlowMap.group_id == group_id).order_by(desc('created_date')).limit(1)
                ret = await session.execute(stmt)
                saved_flow = ret.scalars().one_or_none()
        return saved_flow

