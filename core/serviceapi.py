import logging
from core.observer import Observer
from persistence.models.flow import ObHttpFlow
from mitmproxy import http


class ObserverServiceAPI:
    """This class is the interface to the vulnerability assessment service"""

    def __init__(self) -> None:
        # Collect all attack templates
        self.observer = Observer()

    def clean(self):
        self.observer.clean()
    
    async def handle_request(self, flow: http.HTTPFlow) -> None:
        f = ObHttpFlow(flow=flow)
        if f.all_parameters is None:
            return
        await self.observer.handle_request(f)

    async def handle_response(self,  flow: http.HTTPFlow) -> None:
        f = ObHttpFlow(flow=flow)
        #if f.all_parameters is None:
        #    return
        await self.observer.handle_response(f)
