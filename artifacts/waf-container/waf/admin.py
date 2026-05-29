from django.contrib import admin
from waf.models import BlockedIP, SecurityEvent, RequestLog, TrustedIP


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'reason', 'blocked_at', 'expires_at', 'unique_urls_count', 'is_active']
    list_filter = ['is_active', 'reason']
    search_fields = ['ip_address']
    actions = ['unblock_ips']

    def unblock_ips(self, request, queryset):
        queryset.update(is_active=False)
    unblock_ips.short_description = 'Разблокировать выбранные IP'


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'event_type', 'source_ip', 'url', 'status_code']
    list_filter = ['event_type']
    search_fields = ['source_ip', 'url']
    readonly_fields = ['timestamp']


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'source_ip', 'method', 'url', 'status_code', 'was_blocked']
    list_filter = ['was_blocked', 'method']
    search_fields = ['source_ip', 'url']
    readonly_fields = ['timestamp']


@admin.register(TrustedIP)
class TrustedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_or_subnet', 'description', 'added_at']
    search_fields = ['ip_or_subnet', 'description']
