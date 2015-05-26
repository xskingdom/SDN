# Copyright (C) 2014 Stratosphere Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""

Connect to this application by WebSocket (use your favorite client):
$ wscat -c ws://localhost:8080/v1.0/topology/ws

"""  # noqa

from socket import error as SocketError
from ryu.contrib.tinyrpc.exc import InvalidReplyError


from ryu.app.wsgi import (
    ControllerBase,
    WSGIApplication,
    websocket,
    WebSocketRPCClient
)
from ryu.base import app_manager
from ryu.app.MaliciousURLsControl import MaliciousURLsControl
from ryu.controller.handler import set_ev_cls,MAIN_DISPATCHER


class WebSocketURLs(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        #'switches': switches.Switches,
    }

    def __init__(self, *args, **kwargs):
        super(WebSocketURLs, self).__init__(*args, **kwargs)

        self.rpc_clients = []

        wsgi = kwargs['wsgi']
        wsgi.register(WebSocketURLsController, {'app': self})

    @set_ev_cls(MaliciousURLsControl.EventURLsReqRecord, MAIN_DISPATCHER)
    def _event_url_handler(self, ev):
        msg = ev.URLs
        print msg
        self._rpc_broadcall('event_urls_record', msg)

    def _rpc_broadcall(self, func_name, msg):
        disconnected_clients = []
        for rpc_client in self.rpc_clients:
            # NOTE: Although broadcasting is desired,
            #       RPCClient#get_proxy(one_way=True) does not work well
            rpc_server = rpc_client.get_proxy()
            try:
                getattr(rpc_server, func_name)(msg)
                print getattr(rpc_server, func_name)
            except SocketError:
                self.logger.debug('WebSocket disconnected: %s', rpc_client.ws)
                disconnected_clients.append(rpc_client)
            except InvalidReplyError as e:
                self.logger.error(e)

        for client in disconnected_clients:
            self.rpc_clients.remove(client)


class WebSocketURLsController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(WebSocketURLsController, self).__init__(
            req, link, data, **config)
        self.app = data['app']

    @websocket('Malicious', '/Malicious/ws')
    def _websocket_handler(self, ws):
        rpc_client = WebSocketRPCClient(ws)
        self.app.rpc_clients.append(rpc_client)
        rpc_client.serve_forever()
