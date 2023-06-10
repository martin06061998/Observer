

import logging

from sqlalchemy import update
from persistence.models.param import Parameter, ParamFlowMap
from persistence.models.flow import ObHttpFlow
from persistence.database import db_session
from sqlalchemy.future import select


class ParameterDao:
    def __init__(self) -> None:
        pass

    async def insert_parameter(self, new_parameter: Parameter = None, param: str = None, flow: ObHttpFlow = None):
        if new_parameter is None:
            if param is None or flow is None:
                return
            new_parameter = Parameter.new_parameter(param, flow)
        async_session = await db_session()
        async with async_session() as session:
            async with session.begin():
                session.add(new_parameter)
                await session.commit()
        return new_parameter

    async def add_param_flow(self, parameter_id: str, flow_id: str):
        param_flow = ParamFlowMap(
            parameter_id=parameter_id, flow_id=flow_id)
        async_session = await db_session()
        ret = None
        async with async_session() as session:
            async with session.begin():
                session.add(param_flow)
                await session.commit()
        return ret

    async def get_parameter_by_id(self, id: str):
        async_session = await db_session()
        ret = None
        async with async_session() as session:
            async with session.begin():
                stmt = select(Parameter).where(Parameter.id == id)
                ret = await session.execute(stmt)
                saved_parameter = ret.scalars().first()
        return saved_parameter

    async def add_example_value(self, parameter_id: str, value: str):
        async_session = await db_session()
        ret = None
        async with async_session() as session:
            async with session.begin():
                stmt = select(Parameter).where(Parameter.id == parameter_id)
                ret = await session.execute(stmt)
                saved_parameter: Parameter = ret.scalars().one()
                if saved_parameter:
                    example_values = saved_parameter.example_values
                    if example_values:
                        example_values.append(value)
                        example_values = [*set(example_values)]
                    else:
                        example_values = [value]
                    update_statement = update(Parameter).values(
                        {"example_values": example_values}).where(Parameter.id == parameter_id)
                    await session.execute(update_statement)
                await session.commit()
        return saved_parameter
