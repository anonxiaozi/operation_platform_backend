# -*- coding: utf-8 -*-
# @Time: 2020/4/1
# @File: utils

from .models import BlackListedToken
import logging
import datetime
import os
from django.conf import settings


class TokenOP(object):

    def __init__(self, user, token):
        self.user = user
        self.token = token

    def is_valid_token(self):
        """
        检查user -> token是否存在黑名单中
        """
        is_allowed_user = True
        try:
            is_blackListed = BlackListedToken.objects.get(user=self.user, token=self.token)
            if is_blackListed:
                is_allowed_user = False
        except Exception:
            is_allowed_user = True
        finally:
            return is_allowed_user

    def append_to_black_list(self):
        """
        将user及对应的token加入黑名单
        """
        try:
            BlackListedToken.objects.create(token=self.token, user=self.user)
        except Exception as e:
            print(e)


def Logger(log_name="{}.log".format(datetime.datetime.now().strftime("%Y_%m_%d")), level=10):

    """level
    CRITICAL = 50
    FATAL = CRITICAL
    ERROR = 40
    WARNING = 30
    WARN = WARNING
    INFO = 20
    DEBUG = 10
    NOTSET = 0
    """

    LOGDIR = settings.BASE_DIR + os.sep + 'logs'
    if not os.path.exists(LOGDIR):
        os.mkdir(LOGDIR)
    logger = logging.getLogger("operation_platform")
    formatter = logging.Formatter(fmt="%(asctime)s %(levelname)s %(message)s   [%(filename)s:%(lineno)s]")
    fh = logging.FileHandler(os.path.join(LOGDIR, log_name), "a")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.setLevel(level)
    return logger