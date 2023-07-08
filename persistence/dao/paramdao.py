

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
    
    async def get_parameters_by_name(self, name: str):
        async_session = await db_session()
        ret = None
        saved_parameter = None
        async with async_session() as session:
            async with session.begin():
                stmt = select(Parameter).filter(Parameter.name.like(f"%{name}%")).limit(10)
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

    
    async def add_param_flow(self, parameter_id: str, flow_id: str):
        new_map = ParamFlowMap(parameter_id,flow_id)
        await add(new_map)

    
    async def get_last_param_flow(self,parameter_id:str)->ParamFlowMap:
        async_session = await db_session()
        ret = None
        saved_flow = None
        async with async_session() as session:
            async with session.begin():
                stmt = select(ParamFlowMap).where(ParamFlowMap.parameter_id == parameter_id).order_by(desc('created_date')).limit(1)
                ret = await session.execute(stmt)
                saved_flow = ret.scalars().one_or_none()
        return saved_flow