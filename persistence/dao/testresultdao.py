
import logging

from sqlalchemy import desc, update
from persistence.models.param import Parameter, ParamFlowMap
from persistence.models.flow import ObHttpFlow
from persistence.database import db_session,add
from sqlalchemy.future import select
from persistence.models.testresult import TestResult


class TestResultDao:
    def __init__(self) -> None:
        pass

    async def insert_test_result(self, test_result:TestResult):
        if test_result is None or not isinstance(test_result,TestResult):
            return
        await add(test_result)
        return test_result
    
    async def search_vulnerable_parameters_by_bug_type(self,name,endpoint,bug_type,is_vulnerable,is_tested,limit,template_path):
        async_session = await db_session()
        ret = None
        saved_test_results = None
        async with async_session() as session:
            async with session.begin():
                if not is_tested:
                    is_vulnerable = None
                stmt = select(Parameter.id,Parameter.name,Parameter.endpoint,TestResult.bug_type,TestResult.template_path,TestResult.payloads).filter(Parameter.id == TestResult.parameter_id).filter(Parameter.name.like(f"%{name}%")).filter(TestResult.is_vulnerable == is_vulnerable).filter(TestResult.bug_type.like(f"%{bug_type}%")).filter(Parameter.endpoint.like(f"%{endpoint}%")).filter(TestResult.template_path.like(f"%{template_path}%")).limit(limit)
                saved_test_results = await session.execute(stmt)
            ret = [row for row in saved_test_results]

        return ret