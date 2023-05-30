import asyncio
import logging
from mitmproxy import http
from core.serviceapi import ObserverServiceAPI
from mitmproxy import ctx


class FlowInterceptor:
    def __init__(self):
        self.service_api = ObserverServiceAPI()

    def running(self):
        ctx.master.commands.call("set", "client_replay_concurrency", 1)

    def done(self):
        pass

    def handle_preflight(self, flow: http.HTTPFlow) -> None:
        flow.response = http.Response.make(
            200,
            b"OK",  # (optional) content
            {"Content-Type": "text/html", "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*"},
        )

    
    async def request(self, flow: http.HTTPFlow) -> None:
        """This function is called when a client request has been received. We do the injection here."""
        # Handle DOM Report
        self.service_api.handle_request(flow)


    def response(self, flow: http.HTTPFlow) -> None:
        """This function is called when a server response has been received. We do the analysis here."""
        self.service_api.handle_response(flow)
