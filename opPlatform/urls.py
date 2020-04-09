#!/usr/bin/env python
# coding=utf-8
# Author: bloke

from django.urls import path
from .views import HostView, MyLoginView, LogoutView, SiteView, ExternalView
from django.views.decorators.csrf import csrf_exempt


app_name = 'opPlatform'

urlpatterns = [
    path('', csrf_exempt(HostView.as_view()), name='hosts'),
    path('login/', csrf_exempt(MyLoginView.as_view()), name='login'),
    path('logout/', csrf_exempt(LogoutView.as_view()), name='logout'),
    path('sites/', csrf_exempt(SiteView.as_view()), name='sites'),
    path('external/', csrf_exempt(ExternalView.as_view()), name='external'),
]
