import asyncio
import os
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
ATTRIBUTE_TABLE = dict()
ATTRIBUTE_TABLE['timestamp'] = "timestamp"
ATTRIBUTE_TABLE['status_code'] = "status_code"
ATTRIBUTE_TABLE['response_body_content'] = "response_body_content"
ATTRIBUTE_TABLE['request_headers'] = "_request_headers"

LOOP = asyncio.get_event_loop()
CRAWLER_PORT = 5554
CRAWLER_SERVICE = f"http://127.0.0.1:{CRAWLER_PORT}"
INTRUDER_PORT = 5555
INTRUDER_SERVICE = f"http://127.0.0.1:{INTRUDER_PORT}"
