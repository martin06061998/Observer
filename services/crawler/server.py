import asyncio
import logging
from quart import Quart, request 
from services.network import request as r
from utilities.util import base64_encode,dict_to_url_encoded,dict_to_multipart_form
from definitions import CRAWLER_PORT
import json


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
        
        encoded_data = None
        if data:
            body_type = None
            if "content-type" in headers:
                body_type = headers["content-type"]
            else:
                logging.error(f"Can not define data type")
                return {"msg":"data error"}
        
            if "application/x-www-form-urlencoded" in body_type:
                encoded_data = dict_to_url_encoded(data=data)
            elif "application/json" in body_type:
                encoded_data = json.dumps(data)
            elif "multipart/form-data" in body_type:
                encoded_parameters = {}
                for key,value in data.items():
                    encoded_key = key.encode()
                    encoded_value = value.encode()
                    encoded_parameters[encoded_key] = encoded_value
                encoded_data = dict_to_multipart_form(encoded_parameters)
        async with semaphore:
            ret = await r(method=method,end_point=end_point,headers=headers,params=params,data=encoded_data,timeout=timeout,browser=browser)
        if ret is None:
            return {"msg":"data error"}
        ret["msg"] = "ok"
        ret["content"]=base64_encode(ret.get("content"))
        return ret
    except Exception as e:
        logging.error(f"an error hash occur: {str(e)}")
        return {"msg":"an error hash occur"}
    

if __name__ == "__main__":
    semaphore = asyncio.Semaphore(LIMIT)
    loop = asyncio.get_event_loop()
    app.run(port=CRAWLER_PORT, loop=loop)
