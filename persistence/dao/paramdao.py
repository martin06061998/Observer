

import logging

from sqlalchemy import desc, update
from persistence.models.param import Parameter, ParamFlowMap
from persistence.models.flow import ObHttpFlow
from persistence.database import db_session,add
from sqlalchemy.future import select


class ParameterDao:
    def __init__(self) -> None:
        pass

    async def insert_parameter(self, new_parameter: Parameter = None):
        if new_parameter is None:
            return
        await add(new_parameter)
        return new_parameter


    async def get_parameter_by_id(self, id: str):
        async_session = await db_session()
        ret = None
        saved_parameter = None
        async with async_session() as session:
            async with session.begin():
                stmt = select(Parameter).where(Parameter.id == id)
                ret = await session.execute(stmt)
                saved_parameter = ret.scalars().one_or_none()
        return saved_parameter
    
    async def search_parameters(self, name:str,enctype:str,endpoint:str,data_type:str,limit:int=10):
        async_session = await db_session()
        ret = None
        saved_parameter = None
        async with async_session() as session:
            async with session.begin():
                stmt = select(Parameter).filter(Parameter.name.like(f"%{name}%")).filter(Parameter.body_data_type.like(f"%{enctype}%")).filter(Parameter.endpoint.like(f"%{endpoint}%")).filter(Parameter.data_type.like(f"%{data_type}%")).limit(limit)
                saved_parameter = await session.execute(stmt)
            ret = []
            for row in saved_parameter:
                ret.append(row[0])    
        return ret
    
    async def get_parameters_by_group_id(self,id:str):
        async_session = await db_session()
        ret = None
        saved_parameter = None
        async with async_session() as session:
            async with session.begin():
                stmt = select(Parameter).where(Parameter.group == id)
                saved_parameter = await session.execute(stmt)
            ret = []
            for row in saved_parameter:
                ret.append(row[0])    
        return ret

    
    async def insert_param_flow(self, group_id: str, flow_id: str):
        new_map = ParamFlowMap(group_id,flow_id)
        await add(new_map)

    