# -*- coding: utf-8 -*-
# @Time: 2020/3/25
# @File: routing

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.sessions import SessionMiddlewareStack
from channels.auth import AuthMiddlewareStack
import opPlatform.routing

application = ProtocolTypeRouter({
    # (http->django views is added by default)
    'websocket': SessionMiddlewareStack(
        URLRouter(
            opPlatform.routing.websocket_urlpatterns
        )
    )
})