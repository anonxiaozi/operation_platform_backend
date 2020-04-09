# -*- coding: utf-8 -*-
# @Time: 2020/3/25
# @File: routing

from django.urls import re_path

from . import consumers

websocket_urlpatterns = [
    re_path(r'connect/(?P<ip_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/$', consumers.SSHConsumer)
]