# quart_basic.py
import base64
from quart import Quart
from quart import request
from playwright.async_api import async_playwright
from definitions import INIT_SCRIPT
app = Quart(__name__)


async def __render_html(url: str) -> str:
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        #await page.add_init_script(script=INIT_SCRIPT)
        await page.goto(url)
        await page.wait_for_load_state("domcontentloaded")
        return await page.content()


@app.route("/render-html", methods=['POST'])
async def render_html():
    # await (request.get_data())
    data = await (request.get_json())
    error_message = r'{"error":"true"}'
    if data:
        url = data["url"]
        content = await __render_html(url)
        message_bytes = content.encode('utf-8', "ignore")
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('utf-8', 'ignore')
        return {"url": f"{url}", "content": f"{base64_message}"}
    return error_message


def start_point():
    app.run()