import logging
import time
from playwright.async_api import async_playwright,Route



async def render_html(method:str=None,base_url:str=None,headers:dict[str:str]=None,params:str=None,data:str=None) -> dict:
    async def handler(route: Route):
        # Fetch original response.
        if "tag" in route.request.headers:
            response = await route.fetch(url=base_url,method=method,post_data=data)
        else:
            response = await route.fetch(url=route.request.url,method=method)
        # Add a prefix to the title.
        body = await response.body()
        content_type = response.headers.get("content-type")
        await route.fulfill(
            # Pass all fields from the response.
            response=response,
            # Override response body.
            body=body,
            # Force content type to be html.
            headers={**response.headers},
            content_type=content_type
        )

    proxy = {
      "server":"http://127.0.0.1:8080"  
    }
    
    if params:
        base_url = f"{base_url}?{params}"
    
    async with async_playwright() as playwright:

        try:
            browser = await playwright.chromium.launch(headless=True,args=["--use-gl=egl"],proxy=proxy) 
            context = await browser.new_context(bypass_csp=True,ignore_https_errors=True,extra_http_headers=headers,proxy=proxy)
            page = await context.new_page()
            start = time.time() 
            await page.route(base_url,handler)
            response = await page.goto(url=base_url,wait_until="domcontentloaded")
            #page.wait_for_load_state("domcontentloaded")
            end=time.time()
            content = await page.content()
            content = content.encode("utf-8","ignore")
            status_code =  response.status
            headers = response.headers
            elapsed=end-start
            await browser.close()
        except Exception as e:
            content=None
            status_code = None
            elapsed=None
            end=None
            headers = None
            logging.warning(str(e))
    return {
        "content":content,
        "status_code":status_code,
        "elapsed":elapsed,
        "headers":headers
    }