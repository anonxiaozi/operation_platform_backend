from django.contrib import admin
from .models import HostInfo, SiteUrl, External


# Register your models here.


@admin.register(HostInfo)
class HostInfoAdmin(admin.ModelAdmin):
    fieldsets = [
        ('Key Information',
         {'fields': ['host_name', 'host_user', 'host_addr', 'host_port', 'host_key', 'host_os', 'physical_equipment']}),
        ('Extra Information', {'fields': ['host_remarks', 'host_spec']})
    ]
    list_per_page = 8
    list_display = (
    'host_name', 'host_user', 'host_addr', 'host_port', 'host_key', 'host_os', 'physical_equipment', 'host_createTime')
    search_fields = ['host_name', 'host_addr']


@admin.register(SiteUrl)
class SiteUrlAdmin(admin.ModelAdmin):
    list_per_page = 8
    list_display = (
        'site_name', 'site_url', 'site_tags', 'site_remarks'
    )
    search_fields = ['site_name', 'site_url', 'site_tags']


@admin.register(External)
class ExternalUrlAdmin(admin.ModelAdmin):
    list_per_page = 8
    list_display = (
        'external_name', 'external_url'
    )
    search_fields = ['external_name', 'external_url']
