import json
import random
import time
from datetime import timedelta

from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db.models import Count, Q

from waf.models import BlockedIP, SecurityEvent, RequestLog, TrustedIP
from waf.protection import ProtectionEngine


def dashboard(request):
    engine = ProtectionEngine.get_instance()
    now = timezone.now()
    last_hour = now - timedelta(hours=1)
    last_day = now - timedelta(days=1)

    total_requests = RequestLog.objects.count()
    blocked_requests = RequestLog.objects.filter(was_blocked=True).count()
    active_blocks = BlockedIP.objects.filter(is_active=True).count()
    events_today = SecurityEvent.objects.filter(timestamp__gte=now.replace(hour=0, minute=0, second=0)).count()
    attacks_last_hour = SecurityEvent.objects.filter(
        timestamp__gte=last_hour,
        event_type__in=['attack_detected', 'scan_detected']
    ).count()
    requests_last_hour = RequestLog.objects.filter(timestamp__gte=last_hour).count()
    blocked_last_hour = RequestLog.objects.filter(timestamp__gte=last_hour, was_blocked=True).count()

    recent_events = SecurityEvent.objects.select_related().order_by('-timestamp')[:15]
    top_ips = (
        RequestLog.objects.filter(timestamp__gte=last_day)
        .values('source_ip')
        .annotate(total=Count('id'), blocked=Count('id', filter=Q(was_blocked=True)))
        .order_by('-total')[:10]
    )
    active_block_list = BlockedIP.objects.filter(is_active=True).order_by('-blocked_at')[:20]

    hourly_data = []
    for i in range(23, -1, -1):
        hour_start = now - timedelta(hours=i + 1)
        hour_end = now - timedelta(hours=i)
        total = RequestLog.objects.filter(timestamp__gte=hour_start, timestamp__lt=hour_end).count()
        blocked = RequestLog.objects.filter(
            timestamp__gte=hour_start, timestamp__lt=hour_end, was_blocked=True
        ).count()
        hourly_data.append({
            'label': hour_start.strftime('%H:00'),
            'total': total,
            'blocked': blocked,
        })

    block_reasons = (
        BlockedIP.objects.filter(is_active=True)
        .values('reason')
        .annotate(count=Count('id'))
    )
    reason_labels = []
    reason_counts = []
    reason_map = {
        'unique_url_limit': 'Лимит уникальных URL',
        'error_rate_limit': 'Лимит ошибок 404',
        'rps_limit': 'Лимит запросов/сек',
        'manual': 'Ручная блокировка',
    }
    for br in block_reasons:
        reason_labels.append(reason_map.get(br['reason'], br['reason']))
        reason_counts.append(br['count'])

    trackers = engine.get_all_trackers_summary()[:10]

    context = {
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'active_blocks': active_blocks,
        'events_today': events_today,
        'attacks_last_hour': attacks_last_hour,
        'requests_last_hour': requests_last_hour,
        'blocked_last_hour': blocked_last_hour,
        'block_rate': round(blocked_requests / total_requests * 100, 1) if total_requests > 0 else 0,
        'recent_events': recent_events,
        'top_ips': list(top_ips),
        'active_block_list': active_block_list,
        'hourly_labels': json.dumps([d['label'] for d in hourly_data]),
        'hourly_totals': json.dumps([d['total'] for d in hourly_data]),
        'hourly_blocked': json.dumps([d['blocked'] for d in hourly_data]),
        'reason_labels': json.dumps(reason_labels),
        'reason_counts': json.dumps(reason_counts),
        'config': engine.config,
        'live_trackers': trackers,
        'mode': engine.config.get('mode', 'block'),
        'thresholds': engine.config.get('thresholds', {}),
        'backend_url': engine.config.get('backend_url', '(не настроен)'),
    }
    return render(request, 'waf/dashboard.html', context)


def events_list(request):
    events = SecurityEvent.objects.order_by('-timestamp')[:200]
    return render(request, 'waf/events.html', {'events': events})


def blocked_ips(request):
    blocks = BlockedIP.objects.order_by('-blocked_at')[:100]
    return render(request, 'waf/blocked_ips.html', {'blocks': blocks})


def api_stats(request):
    engine = ProtectionEngine.get_instance()
    now = timezone.now()
    last_hour = now - timedelta(hours=1)

    total = RequestLog.objects.count()
    blocked = RequestLog.objects.filter(was_blocked=True).count()
    active_blocks = BlockedIP.objects.filter(is_active=True).count()
    events_hour = SecurityEvent.objects.filter(timestamp__gte=last_hour).count()
    attacks_hour = SecurityEvent.objects.filter(
        timestamp__gte=last_hour,
        event_type__in=['attack_detected', 'blocked_request']
    ).count()
    recent_logs = RequestLog.objects.filter(timestamp__gte=last_hour)
    req_hour = recent_logs.count()
    blocked_hour = recent_logs.filter(was_blocked=True).count()

    trackers = engine.get_all_trackers_summary()[:5]

    return JsonResponse({
        'total_requests': total,
        'blocked_requests': blocked,
        'active_blocks': active_blocks,
        'events_last_hour': events_hour,
        'attacks_last_hour': attacks_hour,
        'requests_last_hour': req_hour,
        'blocked_last_hour': blocked_hour,
        'block_rate': round(blocked / total * 100, 1) if total > 0 else 0,
        'live_trackers': trackers,
        'mode': engine.config.get('mode', 'block'),
        'timestamp': now.isoformat(),
    })


def api_events(request):
    limit = min(int(request.GET.get('limit', 50)), 200)
    event_type = request.GET.get('type', '')
    qs = SecurityEvent.objects.order_by('-timestamp')
    if event_type:
        qs = qs.filter(event_type=event_type)
    events = qs[:limit]
    data = [{
        'id': e.id,
        'timestamp': e.timestamp.isoformat(),
        'event_type': e.event_type,
        'event_type_display': e.get_event_type_display(),
        'source_ip': e.source_ip,
        'url': e.url,
        'method': e.method,
        'status_code': e.status_code,
        'unique_urls': e.unique_urls_at_time,
        'requests_in_window': e.requests_in_window,
        'error_rate': e.error_rate,
        'details': e.details,
    } for e in events]
    return JsonResponse({'events': data, 'count': len(data)})


@csrf_exempt
@require_http_methods(['POST'])
def api_block_ip(request):
    try:
        body = json.loads(request.body)
        ip = body.get('ip', '').strip()
        reason = body.get('reason', 'manual')
        duration = int(body.get('duration', 3600))
        if not ip:
            return JsonResponse({'error': 'IP required'}, status=400)
        engine = ProtectionEngine.get_instance()
        engine.manual_block(ip, duration, reason)
        return JsonResponse({'success': True, 'message': f'IP {ip} заблокирован'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
@require_http_methods(['POST'])
def api_unblock_ip(request):
    try:
        body = json.loads(request.body)
        ip = body.get('ip', '').strip()
        if not ip:
            return JsonResponse({'error': 'IP required'}, status=400)
        engine = ProtectionEngine.get_instance()
        engine.manual_unblock(ip)
        return JsonResponse({'success': True, 'message': f'IP {ip} разблокирован'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


def api_config(request):
    engine = ProtectionEngine.get_instance()
    return JsonResponse({
        'config': engine.config,
        'thresholds': engine.config.get('thresholds', {}),
        'mode': engine.config.get('mode', 'block'),
        'backend_url': engine.config.get('backend_url', ''),
        'window_seconds': engine.config.get('window_seconds', 60),
        'whitelist': engine.config.get('whitelist', []),
    })


@csrf_exempt
@require_http_methods(['POST'])
def api_simulate_attack(request):
    try:
        body = json.loads(request.body)
        ip = body.get('ip', f'192.168.{random.randint(1,254)}.{random.randint(2,254)}')
        count = min(int(body.get('count', 60)), 200)
        engine = ProtectionEngine.get_instance()
        paths = [
            '/admin/', '/backup/', '/config/', '/.env', '/wp-admin/',
            '/phpmyadmin/', '/api/v1/users', '/api/v1/admin',
            '/secret/', '/private/', '/uploads/', '/shell.php',
            '/wp-config.php', '/.git/config', '/etc/passwd',
            '/api/v2/tokens', '/dashboard/', '/console/',
        ]
        paths_extended = paths + [f'/path-{i}/' for i in range(count)]
        blocked = False
        for i in range(count):
            url = f'http://example.com{paths_extended[i % len(paths_extended)]}'
            path = paths_extended[i % len(paths_extended)]
            result = engine.check_and_record(ip, url, path, 'GET', 404, 'SimulatedAttackBot/1.0')
            if result['action'] == 'block':
                blocked = True
                break
        stats = engine.get_ip_stats(ip)
        return JsonResponse({
            'success': True,
            'ip': ip,
            'requests_sent': i + 1,
            'blocked': blocked,
            'stats': stats,
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
@require_http_methods(['POST'])
def api_clear_logs(request):
    try:
        RequestLog.objects.all().delete()
        SecurityEvent.objects.all().delete()
        BlockedIP.objects.all().delete()
        engine = ProtectionEngine.get_instance()
        with engine._trackers_lock:
            engine._trackers.clear()
        return JsonResponse({'success': True, 'message': 'Все логи очищены'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
