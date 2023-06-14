import asyncio
import logging
from quart import Quart, request 
from services.network import request as r
from utilities.util import base64_encode
from definitions import CRAWLER_PORT

loop = None
semaphore = None
LIMIT = 8
app = Quart(__name__)
logging.basicConfig(filename="log\crawler.log",
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.WARNING)

@app.route("/busy")
async def is_blocked():
    return {"busy":semaphore.locked()}

@app.errorhandler(ConnectionAbortedError)
def handler(e): 
    logging.warning(f"connection aborted")


@app.route("/request",methods=['POST'])
async def send_request():
    try:
        content:dict = await request.get_json(force=True)
        method=content.get("method",None)
        end_point=content.get("end_point",None)
        if method is None or end_point is None:
            return {"msg":"data error"}
        headers=content.get("headers",None)
        params=content.get("params",None)
        data=content.get("data",None)
        timeout=content.get("timeout",60)
        browser=content.get("browser",False)
        async with semaphore:
            ret = await r(method=method,end_point=end_point,headers=headers,params=params,data=data,timeout=timeout,browser=browser)
        if ret is None:
            return {"msg":"data error"}
        ret["msg"] = "ok"
        ret["content"]=base64_encode(ret.get("content"))
        return ret
    except:
        return {"msg":"an error hash occur"}
    

if __name__ == "__main__":
    semaphore = asyncio.Semaphore(LIMIT)
    loop = asyncio.get_event_loop()
    app.run(port=CRAWLER_PORT, loop=loop)
