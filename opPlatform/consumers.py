# -*- coding: utf-8 -*-
# @Time: 2020/3/25
# @File: consumers

from channels.generic.websocket import WebsocketConsumer
import paramiko
from threading import Thread
import re
from .models import HostInfo
import os
from django.conf import settings
from .views import logger
import traceback


class SSHObject(object):

    def ssh_login_auth(self, hostname, window_size=1024):
        host_obj = HostInfo.objects.filter(host_addr=hostname)
        if not host_obj:
            logger.error('ssh登录 {} 失败：未知主机'.format(hostname))
            return False
        host = host_obj[0]
        self.window_size = window_size
        key_file = self.get_keyfile(host.host_key)
        if not key_file:
            logger.error('ssh登录 {} 失败：没有找到私钥 {}'.format(hostname, host.host_key))
            return False
        private_key = paramiko.RSAKey.from_private_key_file(key_file)
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(hostname=hostname, port=host.host_port, username=host.host_user, pkey=private_key)
        logger.debug('ssh连接 {} 成功'.format(hostname))
        self.ssh_session = self.ssh_connect()
        logger.debug('打开 {} 的ssh会话窗口'.format(hostname))
        return True

    @staticmethod
    def get_keyfile(keyfile):
        key_file = settings.PRIVATE_KEY_DIR + os.sep + keyfile + '.key'
        return key_file if os.path.exists(key_file) else ''

    def ssh_connect(self):
        transport = self.ssh.get_transport()
        ssh_session = transport.open_session()
        ssh_session.get_pty(term='xterm')
        ssh_session.invoke_shell()
        return ssh_session

    def ssh_get_welcome(self):
        data = self.ssh_session.recv(4096).decode('utf-8', 'ignore')
        logger.debug('获取登录信息: {}'.format(data))
        return data

    def ssh_send_data(self, command):
        try:
            logger.debug('执行指令: {}'.format(command))
            self.ssh_session.send(command)
        except OSError:
            logger.error('指令 {} 执行失败: {}'.format(command, traceback.format_exc().__str__()))

    def ssh_recv_data(self, socket):
        while not self.ssh_session.exit_status_ready():  # 确保会话在线
            data = self.ssh_session.recv(self.window_size).decode('utf-8', 'ignore')
            if data:
                socket.send(data)
            else:
                break
        else:
            logger.debug('关闭socket')
            socket.close()

    def ssh_call_shell(self, command, socket):
        send = Thread(target=self.ssh_send_data, args=(command,))
        recv = Thread(target=self.ssh_recv_data, args=(socket,))
        for thread in [send, recv]:
            thread.daemon = True
            thread.start()


class SSHConsumer(WebsocketConsumer, SSHObject):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resize_sign = 'bloke_term_resize,' # 修改终端大小的前缀
        self.resize_re = re.compile(r'height=(.+?)width=(.+?);')

    def connect(self):
        self.addr = self.scope['url_route']['kwargs']['ip_addr']
        logger.info('连接到 {}'.format(self.addr))
        sign = self.ssh_login_auth(hostname=self.addr)
        if not sign:
            self.disconnect('500')
            return
        self.accept()
        welcome_data = self.ssh_get_welcome()
        self.send(text_data=welcome_data + '\n')

    def disconnect(self, close_code):
        try:
            logger.debug('断开连接 {}'.format(self.addr))
            self.send('Disconnect from {}'.format(self.addr))
        except Exception:
            logger.debug('断开连接失败: {}'.format(traceback.format_exc().__str__()))
        finally:
            logger.debug('连接 {} 失败'.format(self.addr))
            self.send('连接失败')
            self.ssh_session.close()

    def receive(self, text_data):
        if text_data.startswith(self.resize_sign):
            height, width = self.resize_re.findall(text_data.lstrip(self.resize_sign))[0]
            try:
                logger.debug('调整窗口大小: {}:{}'.format(height, width))
                self.ssh_session.resize_pty(height=int(height), width=int(width))
            except Exception as e:
                logger.error('调整窗口大小({}:{})失败: {}'.format(height, width, traceback.format_exc().__str__()))
        else:
            logger.debug('调整窗口大小成功')
            self.ssh_call_shell(text_data, self)

