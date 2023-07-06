import asyncio
import logging
import multiprocessing
from quart import Quart, request
from werkzeug.routing import BaseConverter
from services.intruder.templater.template import build_vector_table
from persistence.dal import get_data_access_layer_instance
from persistence.models.attackvector import AttackVector
from definitions import INTRUDER_PORT
from concurrent.futures import ProcessPoolExecutor

vector_list : list[AttackVector]=  []
loop = None
LIMIT = 4
POOL = None
m = None
lock = None

#process_pool: list[Process] = []
SEMAPHORE = asyncio.Semaphore(LIMIT*2)
app = Quart(__name__)

logging.basicConfig(filename="log\error.log",
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.WARNING)


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]

app.url_map.converters['regex'] = RegexConverter



async def try_exploit(content: dict[str, str]):
    # SUSPEND THIS TASK TO PREVENT QUART SERVER FROM BEING BLOCKED
    await asyncio.sleep(0.2)

    # PREPARE DATA BEFORE ASSESSMENT
    dal = get_data_access_layer_instance()
    
    parameter_id = content["parameter_id"]
    saved_param = await dal.get_parameter_by_id(parameter_id)
    if saved_param is None:
        logging.warning(f"parameter id {parameter_id} not exists")
        return
    flow_id = saved_param.request_template_id
    saved_flow = await dal.get_flow_by_id(flow_id)
    if saved_flow is None:
        return
    
    TASKS = []
    
    for vector in vector_list:
        TASKS.append(loop.run_in_executor(POOL, vector.exploit, saved_flow,saved_param,lock))
    
    asyncio.gather(*TASKS)

@app.route("/exploit", methods=['POST'])
async def exploit():
    content = await request.get_json()
    app.add_background_task(func=try_exploit, content=content)
    return {"msg": "OK"}


if __name__ == "__main__":
    POOL = ProcessPoolExecutor(max_workers=LIMIT)
    m = multiprocessing.Manager()
    lock = m.Lock()
    loop = asyncio.get_event_loop()
    loop.create_task(build_vector_table(vector_list=vector_list))
    app.run(port=INTRUDER_PORT, loop=loop)
