from persistence.database import initialize
from mitmproxy import http
from core.serviceapi import ObserverServiceAPI
from mitmproxy import ctx


class FlowInterceptor:
    def __init__(self):
        self.service_api = ObserverServiceAPI()

    async def running(self):
        await initialize()
        ctx.master.commands.call("set", "client_replay_concurrency", 1)

    def done(self):
        self.service_api.clean()


    async def request(self, flow: http.HTTPFlow) -> None:
        """This function is called when a client request has been received. We do the injection here."""
        # Handle DOM Report
        flow.request.headers["user-agent"] = "HackerOne_m4rt1n98"
        await self.service_api.handle_request(flow)

    async def response(self, flow: http.HTTPFlow) -> None:
        """This function is called when a server response has been received. We do the analysis here."""
        await self.service_api.handle_response(flow)
     
