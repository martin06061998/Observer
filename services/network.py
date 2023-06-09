import httpx
import time
from playwright.sync_api import sync_playwright,Route
from utilities.util import dict_to_url_encoded,dict_to_multipart_form,base64_encode
import json

def __browserless_request(method:str,end_point:str,headers:dict[str:str]=None,data:str|bytes=None,timeout:float=None,proxy:str=None) -> dict:
    def handler(route: Route):
        # Fetch original response.
        timeout = 45000
        response =  route.fetch(url=end_point,method=method,post_data=data,timeout=timeout)

        # Add a prefix to the title.
        body =  response.body()
        content_type = response.headers.get("content-type")
        route.fulfill(
            response=response,
            body=body,
            headers={**response.headers},
            content_type=content_type
        )
    if proxy:
        proxy = {
        "server":proxy 
        }
    

    with sync_playwright() as playwright:
        browser =  playwright.chromium.launch(headless=True,args=["--use-gl=egl"],proxy=proxy) 
        context =  browser.new_context(bypass_csp=True,ignore_https_errors=True,extra_http_headers=headers,proxy=proxy)
        page =  context.new_page()
        start = time.time() 
        page.route(end_point,handler)
        timeout=timeout*1000 if timeout else 45000
        response =  page.goto(url=end_point,wait_until="domcontentloaded",timeout=timeout)
        end=time.time()
        content =  page.content()
        status_code =  response.status
        response_headers = response.headers
        elapsed=end-start
        browser.close()

    return {
        "content":content,
        "status_code":status_code,
        "elapsed":elapsed,
        "response_headers":response_headers
    }

def __httpx_request(method:str,end_point:str,headers:str,params:dict[str:str]=None,data:bytes|str=None,timeout:float=None,proxy:str=None):

    with httpx.Client(verify=False,proxies=proxy) as client:
        r : httpx.Response = client.request(url= end_point,method=method,params=params,headers=headers,data=data,timeout=timeout)
        content = r.text
        response_headers = r.headers
        status_code = r.status_code
        elapsed = r.elapsed.total_seconds()
        
        #email.utils.parsedate_to_datetime(text)
        return {
            "content":content,
            "response_headers": {**response_headers},
            "status_code":status_code,
            "elapsed":elapsed
        }
    
def __request(method:str,end_point:str,headers:str=None,params:dict[str:str]=None,data:dict[str:str]=None,timeout:float=None,javascript_enable:bool=False,proxy:str=None):
    r=None
    if javascript_enable:
        if params:
            encoded_params=dict_to_url_encoded(params)
            encoded_params = encoded_params.decode("utf-8")
            end_point = end_point.split("?")[0]
            end_point=f"{end_point}?{encoded_params}"
        r : dict =  __browserless_request(end_point= end_point,method=method,headers=headers,data=data,proxy=proxy,timeout=timeout)
    else:
        r =  __httpx_request(method=method,end_point=end_point,headers=headers,params=params,data=data,timeout=timeout,proxy=proxy)
    return r


def encode_data(data:dict,enctype):
    if "application/x-www-form-urlencoded" in enctype:
        encoded_data = dict_to_url_encoded(data=data)
    elif "application/json" in enctype:
        encoded_data = json.dumps(data)
    elif "multipart/form-data" in enctype:
        encoded_parameters = {}
        for key,value in data.items():
            encoded_key = key.encode()
            encoded_value = value.encode()
            encoded_parameters[encoded_key] = encoded_value
        encoded_data = dict_to_multipart_form(encoded_parameters)
    return encoded_data



def request(method:str,end_point:str,headers:dict[str:str]=None,params:dict[str:str]=None,data:dict[str:str]=None,timeout:float=None,javascript_enable:bool=False,proxy:str=None,enctype:str=None):
    encoded_data = None
    if data:
        encoded_data = encode_data(data=data,enctype=enctype)
        headers["content-type"] = enctype
    ret = __request(method=method,end_point=end_point,headers=headers,params=params,data=encoded_data,timeout=timeout,javascript_enable=javascript_enable,proxy=proxy)
    ret["content"]=base64_encode(ret.get("content"))
    return ret