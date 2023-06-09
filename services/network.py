import httpx
import logging
import time
from playwright.async_api import async_playwright,Route
from utilities.util import dict_to_url_encoded
import asyncio

async def browserless_request(method:str,end_point:str,headers:dict[str:str]=None,data:str=None,timeout:float=None,proxy:str="http://127.0.0.1:8080") -> dict:
    async def handler(route: Route):
        # Fetch original response.
        if "tag" in route.request.headers:
            response = await route.fetch(url=end_point,method=method,post_data=data)
        else:
            response = await route.fetch(url=route.request.url,method=method)
        # Add a prefix to the title.
        body = await response.body()
        content_type = response.headers.get("content-type")
        await route.fulfill(
            response=response,
            body=body,
            headers={**response.headers},
            content_type=content_type
        )

    proxy = {
      "server":proxy 
    }
    

    
    async with async_playwright() as playwright:

        try:
            browser = await playwright.chromium.launch(headless=True,args=["--use-gl=egl"],proxy=proxy) 
            context = await browser.new_context(bypass_csp=True,ignore_https_errors=True,extra_http_headers=headers,proxy=proxy)
            page = await context.new_page()
            start = time.time() 
            await page.route(end_point,handler)
            #timeout=timeout*1000 if timeout else None
            response = await page.goto(url=end_point,wait_until="domcontentloaded",timeout=timeout)
            end=time.time()
            content = await page.content()
            content = content.encode("utf-8","ignore")
            status_code =  response.status
            response_headers = response.headers
            elapsed=end-start
            await browser.close()
        except Exception as e:
            content=None
            status_code = None
            elapsed=None
            end=None
            response_headers = None
            logging.warning(str(e))
    return {
        "content":content,
        "status_code":status_code,
        "elapsed":elapsed,
        "response_headers":response_headers
    }

async def httpx_request(method:str,end_point:str,headers:str,params:dict[str:str]=None,data:dict[str:str]=None,json:dict[str:str]=None,timeout:float=None,proxy:str="http://127.0.0.1:8080"):
    async with httpx.AsyncClient(verify=False,proxies={"https://":proxy,"http://":proxy}) as client:
        r : httpx.Response = await client.request(url= end_point,method=method,params=params,headers=headers,json=json,data=data,timeout=timeout)
        content = r.content
        response_headers = r.headers
        status_code = r.status_code
        elapsed = r.elapsed.total_seconds()
        return {
            "content":content,
            "response_headers": {**response_headers},
            "status_code":status_code,
            "elapsed":elapsed
        }
    


async def request(method:str,end_point:str,headers:str=None,params:dict[str:str]=None,data:dict[str:str]=None,timeout:float=None,body_type:str="application/x-www-form-urlencoded",browser:bool=False,json=None,proxy:str="http://127.0.0.1:8080"):
    r=None
    if browser:
        encoded_params = None
        encoded_data = None
        if data:
            if body_type == "application/x-www-form-urlencoded":
                encoded_data = dict_to_url_encoded(data=data)
        if params:
            encoded_params=dict_to_url_encoded(params)
            end_point=f"{end_point}?{encoded_params}"
        r : dict = await browserless_request(end_point= end_point,method=method,headers=headers,data=encoded_data,proxy=proxy)
    else:
        r = await httpx_request(method=method,end_point=end_point,headers=headers,params=params,data=data,timeout=timeout,json=json,proxy=proxy)
    
    if r.get("elapsed",None) and r.get("content",None) and r.get("response_headers",None) and r.get("status_code",None):
        return r
    return
   