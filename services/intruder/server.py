import asyncio
import logging
from quart import Quart, request
from werkzeug.routing import BaseConverter
from services.intruder.templater.template import build_vector_table
from persistence.dal import get_data_access_layer_instance
from persistence.models.attackvector import AttackVector

vector_list : list[AttackVector]=  []
loop = None
LIMIT = 20
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
    flow_id = content["flow_id"]
    parameter_id = content["parameter_id"]
    saved_param = await dal.get_parameter_by_id(parameter_id)
    if saved_param is None:
        return
    saved_flow = await dal.get_flow_by_id(flow_id)
    if saved_flow is None:
        return
    # END
    
    pool = []
    
    for vector in vector_list:
        try:
            if len(pool) < LIMIT:
                t = loop.create_task(vector.exploit(flow=saved_flow,parameter=saved_param))
                pool.append(t)
                #await asyncio.sleep(0.2)
            else:
                await asyncio.gather(*pool,return_exceptions=True)
        except Exception as e:
            logging.error(str(e))
        finally:
            pool.clear()



@app.route("/exploit", methods=['POST'])
async def exploit():
    content = await request.get_json()
    app.add_background_task(func=try_exploit, content=content)
    return {"msg": "OK"}


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.create_task(build_vector_table(vector_list=vector_list))
    app.run(port=5555, loop=loop)
