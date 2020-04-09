from django.db import models
from django.contrib.auth.models import User


# Create your models here.


class HostInfo(models.Model):
    host_name = models.CharField('host name', max_length=50)
    host_addr = models.GenericIPAddressField('host address', unique=True, primary_key=True)
    host_user = models.CharField('ssh user', max_length=50, default='root', null=True)
    host_port = models.IntegerField('ssh port', default=22, null=True)
    host_key = models.CharField('ssh private key', max_length=60, default='default', null=True)
    host_remarks = models.CharField('host remarks', max_length=100, null=True)
    physical_equipment = models.BooleanField('physical equipment?')
    host_createTime = models.DateTimeField('create time', auto_now_add=True)
    host_spec = models.CharField('host specifications', max_length=80, null=True)
    host_os = models.CharField(choices=[('win32', 'Windows'), ('linux', 'Linux')], default='win32', max_length=7)

    def __str__(self):
        return self.host_addr


class BlackListedToken(models.Model):

    """
    token黑名单，为简便，直接放到本地使用的db中，不放redis
    """

    token = models.CharField(max_length=500)
    user = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("token", "user")


class SiteUrl(models.Model):
    site_name = models.CharField(max_length=50)
    site_url = models.URLField(unique=True)
    site_remarks = models.CharField(max_length=100, null=True)
    site_tags = models.CharField(max_length=50, default='company')
    auth = models.CharField(max_length=80, default='', null=True)

    def __str__(self):
        return '{} {}'.format(self.site_name, self.site_url)


class External(models.Model):
    external_name = models.CharField(max_length=50)
    external_url = models.URLField(unique=True)
    external_remarks = models.CharField(max_length=200, null=True)
    external_auth = models.CharField(max_length=80, null=True)

    def __str__(self):
        return '{} {}'.format(self.external_name, self.external_url)

