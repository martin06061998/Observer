import asyncio
import os
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
ATTRIBUTE_TABLE = dict()
ATTRIBUTE_TABLE['timestamp'] = "timestamp"
ATTRIBUTE_TABLE['status_code'] = "status_code"
ATTRIBUTE_TABLE['response_body_content'] = "response_body_content"
ATTRIBUTE_TABLE['request_headers'] = "_request_headers"



DOM_HOOK_SCRIPT = None
with open(os.path.join(ROOT_DIR, 'gadget', 'nativeJSHook.js')) as f:
    INIT_SCRIPT = f.read()


LOOP = asyncio.get_event_loop()
