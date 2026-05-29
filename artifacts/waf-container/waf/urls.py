from django.urls import path
from waf import views

app_name = 'waf'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('dashboard/', views.dashboard, name='dashboard_alt'),
    path('events/', views.events_list, name='events'),
    path('blocked-ips/', views.blocked_ips, name='blocked_ips'),
    path('api/stats/', views.api_stats, name='api_stats'),
    path('api/events/', views.api_events, name='api_events'),
    path('api/block-ip/', views.api_block_ip, name='api_block_ip'),
    path('api/unblock-ip/', views.api_unblock_ip, name='api_unblock_ip'),
    path('api/config/', views.api_config, name='api_config'),
    path('api/simulate/', views.api_simulate_attack, name='api_simulate'),
    path('api/clear-logs/', views.api_clear_logs, name='api_clear_logs'),
]
