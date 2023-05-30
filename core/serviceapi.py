import logging
from core.observer import Observer
from persistence.models.flow import ObHttpFlow
from mitmproxy import http


class ObserverServiceAPI:
    """This class is the interface to the vulnerability assessment service"""

    def __init__(self) -> None:
        # Collect all attack templates
        self.observer = Observer()

    def handle_request(self, flow: http.HTTPFlow) -> None:
        f = ObHttpFlow(flow)
        if f.all_parameters is None:
            return
        self.observer.handle_request(f)

    def handle_response(self,  flow: http.HTTPFlow) -> None:
        f = ObHttpFlow(flow)
        if f.all_parameters is None:
            return
        self.observer.handle_response(f)
