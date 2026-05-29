# =============================================================================
# БЛОК ИМПОРТА ЗАВИСИМОСТЕЙ
# =============================================================================
import json
import random
import time
from datetime import timedelta

from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt        # Отключение CSRF для REST API
from django.views.decorators.http import require_http_methods  # Ограничение HTTP-методов
from django.utils import timezone
from django.db.models import Count, Q  # Q — сложные условия запросов (AND/OR/NOT)

from waf.models import BlockedIP, SecurityEvent, RequestLog, TrustedIP
from waf.protection import ProtectionEngine


# =============================================================================
# БЛОК ГЛАВНОГО ДАШБОРДА
# Собирает всю аналитику для HTML-страницы /waf/ за O(N запросов к БД).
# =============================================================================
def dashboard(request):
    """
    Главный дашборд: агрегирует статистику из трёх таблиц БД
    и передаёт в шаблон dashboard.html для визуализации.
    """
    engine = ProtectionEngine.get_instance()  # Доступ к in-memory счётчикам и конфигу
    now = timezone.now()
    last_hour = now - timedelta(hours=1)
    last_day = now - timedelta(days=1)

    # БЛОК АГРЕГАЦИИ KPI-ПОКАЗАТЕЛЕЙ (карточки статистики)
    total_requests = RequestLog.objects.count()                              # Всего запросов в БД
    blocked_requests = RequestLog.objects.filter(was_blocked=True).count()  # Из них заблокировано
    active_blocks = BlockedIP.objects.filter(is_active=True).count()        # Активных блокировок IP
    events_today = SecurityEvent.objects.filter(
        timestamp__gte=now.replace(hour=0, minute=0, second=0)              # События с начала суток
    ).count()
    attacks_last_hour = SecurityEvent.objects.filter(
        timestamp__gte=last_hour,
        event_type__in=['attack_detected', 'scan_detected']                 # Только атаки, не все события
    ).count()
    requests_last_hour = RequestLog.objects.filter(timestamp__gte=last_hour).count()
    blocked_last_hour = RequestLog.objects.filter(
        timestamp__gte=last_hour, was_blocked=True
    ).count()

    # БЛОК ДАННЫХ ДЛЯ ТАБЛИЦ ДАШБОРДА
    # select_related() — JOIN для связанных объектов (избегает N+1 запросов)
    recent_events = SecurityEvent.objects.select_related().order_by('-timestamp')[:15]

    # Топ IP по активности за сутки с аннотацией числа заблокированных запросов
    # Q(was_blocked=True) — условный Count (считает только заблокированные)
    top_ips = (
        RequestLog.objects.filter(timestamp__gte=last_day)
        .values('source_ip')
        .annotate(
            total=Count('id'),
            blocked=Count('id', filter=Q(was_blocked=True))   # Фильтрованный COUNT
        )
        .order_by('-total')[:10]
    )
    active_block_list = BlockedIP.objects.filter(is_active=True).order_by('-blocked_at')[:20]

    # БЛОК ДАННЫХ ДЛЯ ГРАФИКА ТРАФИКА ПО ЧАСАМ (Chart.js, 24 точки)
    hourly_data = []
    for i in range(23, -1, -1):   # От 23 часов назад до текущего часа
        hour_start = now - timedelta(hours=i + 1)
        hour_end = now - timedelta(hours=i)
        total = RequestLog.objects.filter(
            timestamp__gte=hour_start, timestamp__lt=hour_end
        ).count()
        blocked = RequestLog.objects.filter(
            timestamp__gte=hour_start, timestamp__lt=hour_end, was_blocked=True
        ).count()
        hourly_data.append({
            'label': hour_start.strftime('%H:00'),  # Метка оси X: "14:00"
            'total': total,
            'blocked': blocked,
        })

    # БЛОК ДАННЫХ ДЛЯ КРУГОВОЙ ДИАГРАММЫ ПРИЧИН БЛОКИРОВОК
    block_reasons = (
        BlockedIP.objects.filter(is_active=True)
        .values('reason')       # GROUP BY reason
        .annotate(count=Count('id'))  # COUNT(*) для каждой причины
    )
    reason_labels = []
    reason_counts = []
    reason_map = {   # Технические ключи → читаемые названия для легенды
        'unique_url_limit': 'Лимит уникальных URL',
        'error_rate_limit': 'Лимит ошибок 404',
        'rps_limit': 'Лимит запросов/сек',
        'manual': 'Ручная блокировка',
    }
    for br in block_reasons:
        reason_labels.append(reason_map.get(br['reason'], br['reason']))
        reason_counts.append(br['count'])

    # БЛОК LIVE-МОНИТОРИНГА (данные из in-memory трекеров, не из БД)
    trackers = engine.get_all_trackers_summary()[:10]  # Топ-10 активных IP в текущем окне

    # БЛОК ФОРМИРОВАНИЯ КОНТЕКСТА ШАБЛОНА
    # JSON-сериализация данных для Chart.js (передаются в <script> тега шаблона)
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
        # Данные для Chart.js передаются как JSON-строки (|safe в шаблоне)
        'hourly_labels': json.dumps([d['label'] for d in hourly_data]),
        'hourly_totals': json.dumps([d['total'] for d in hourly_data]),
        'hourly_blocked': json.dumps([d['blocked'] for d in hourly_data]),
        'reason_labels': json.dumps(reason_labels),
        'reason_counts': json.dumps(reason_counts),
        'config': engine.config,          # Полный конфиг WAF для отображения в разделе настроек
        'live_trackers': trackers,
        'mode': engine.config.get('mode', 'block'),
        'thresholds': engine.config.get('thresholds', {}),
        'backend_url': engine.config.get('backend_url', '(не настроен)'),
    }
    return render(request, 'waf/dashboard.html', context)  # Рендеринг HTML-шаблона


# =============================================================================
# БЛОК HTML-СТРАНИЦ (ВСПОМОГАТЕЛЬНЫЕ ПРЕДСТАВЛЕНИЯ)
# =============================================================================
def events_list(request):
    """Страница /waf/events/ — полная таблица событий безопасности."""
    events = SecurityEvent.objects.order_by('-timestamp')[:200]
    return render(request, 'waf/events.html', {'events': events})


def blocked_ips(request):
    """Страница /waf/blocked-ips/ — список всех блокировок с управлением."""
    blocks = BlockedIP.objects.order_by('-blocked_at')[:100]
    return render(request, 'waf/blocked_ips.html', {'blocks': blocks})


# =============================================================================
# БЛОК REST API — ПОЛУЧЕНИЕ ДАННЫХ (только GET)
# Используется дашбордом для периодического обновления без перезагрузки страницы.
# =============================================================================
def api_stats(request):
    """
    GET /waf/api/stats/ — сводная статистика для live-обновления дашборда.
    Вызывается каждые 10 секунд из JavaScript через fetch().
    """
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

    trackers = engine.get_all_trackers_summary()[:5]  # Топ-5 активных IP для live-виджета

    return JsonResponse({
        'total_requests': total,
        'blocked_requests': blocked,
        'active_blocks': active_blocks,
        'events_last_hour': events_hour,
        'attacks_last_hour': attacks_hour,
        'requests_last_hour': req_hour,
        'blocked_last_hour': blocked_hour,
        'block_rate': round(blocked / total * 100, 1) if total > 0 else 0,
        'live_trackers': trackers,   # In-memory данные текущего скользящего окна
        'mode': engine.config.get('mode', 'block'),
        'timestamp': now.isoformat(),
    })


def api_events(request):
    """
    GET /waf/api/events/?limit=50&type=attack_detected
    Список событий с опциональной фильтрацией по типу.
    """
    limit = min(int(request.GET.get('limit', 50)), 200)  # Ограничение max 200 записей
    event_type = request.GET.get('type', '')
    qs = SecurityEvent.objects.order_by('-timestamp')
    if event_type:
        qs = qs.filter(event_type=event_type)   # Фильтр по типу события
    events = qs[:limit]
    data = [{
        'id': e.id,
        'timestamp': e.timestamp.isoformat(),
        'event_type': e.event_type,
        'event_type_display': e.get_event_type_display(),  # Читаемое название из choices
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


def api_config(request):
    """GET /waf/api/config/ — текущая конфигурация WAF (только чтение)."""
    engine = ProtectionEngine.get_instance()
    return JsonResponse({
        'config': engine.config,
        'thresholds': engine.config.get('thresholds', {}),
        'mode': engine.config.get('mode', 'block'),
        'backend_url': engine.config.get('backend_url', ''),
        'window_seconds': engine.config.get('window_seconds', 60),
        'whitelist': engine.config.get('whitelist', []),
    })


# =============================================================================
# БЛОК REST API — УПРАВЛЕНИЕ БЛОКИРОВКАМИ (POST-методы)
# @csrf_exempt — CSRF-защита отключена для programmatic API-доступа.
# @require_http_methods(['POST']) — только POST-запросы допустимы.
# =============================================================================
@csrf_exempt
@require_http_methods(['POST'])
def api_block_ip(request):
    """
    POST /waf/api/block-ip/
    Тело: {"ip": "1.2.3.4", "duration": 3600, "reason": "manual"}
    Ручная блокировка IP через дашборд или внешний API.
    """
    try:
        body = json.loads(request.body)   # Разбор JSON-тела запроса
        ip = body.get('ip', '').strip()
        reason = body.get('reason', 'manual')
        duration = int(body.get('duration', 3600))
        if not ip:
            return JsonResponse({'error': 'IP required'}, status=400)
        engine = ProtectionEngine.get_instance()
        engine.manual_block(ip, duration, reason)   # Делегирование движку защиты
        return JsonResponse({'success': True, 'message': f'IP {ip} заблокирован'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
@require_http_methods(['POST'])
def api_unblock_ip(request):
    """
    POST /waf/api/unblock-ip/
    Тело: {"ip": "1.2.3.4"}
    Ручная разблокировка IP и сброс счётчиков трекера.
    """
    try:
        body = json.loads(request.body)
        ip = body.get('ip', '').strip()
        if not ip:
            return JsonResponse({'error': 'IP required'}, status=400)
        engine = ProtectionEngine.get_instance()
        engine.manual_unblock(ip)   # Деактивация в БД + сброс in-memory трекера
        return JsonResponse({'success': True, 'message': f'IP {ip} разблокирован'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


# =============================================================================
# БЛОК СИМУЛЯТОРА АТАКИ (ИНСТРУМЕНТ ТЕСТИРОВАНИЯ)
# Генерирует поток запросов с 404-ответами от случайного IP для демонстрации
# работы механизма обнаружения без реального внешнего трафика.
# =============================================================================
@csrf_exempt
@require_http_methods(['POST'])
def api_simulate_attack(request):
    """
    POST /waf/api/simulate/
    Тело: {"ip": "1.2.3.4", "count": 70}
    Симулирует атаку форсированного браузинга для демонстрации/тестирования.
    Использует тот же движок защиты, что и реальный трафик.
    """
    try:
        body = json.loads(request.body)
        # Генерация случайного IP если не указан — каждый запуск = новая атака
        ip = body.get('ip', f'192.168.{random.randint(1,254)}.{random.randint(2,254)}')
        count = min(int(body.get('count', 60)), 200)  # Максимум 200 запросов за симуляцию
        engine = ProtectionEngine.get_instance()

        # Список типичных URL, используемых при атаке форсированного браузинга
        paths = [
            '/admin/', '/backup/', '/config/', '/.env', '/wp-admin/',
            '/phpmyadmin/', '/api/v1/users', '/api/v1/admin',
            '/secret/', '/private/', '/uploads/', '/shell.php',
            '/wp-config.php', '/.git/config', '/etc/passwd',
            '/api/v2/tokens', '/dashboard/', '/console/',
        ]
        paths_extended = paths + [f'/path-{i}/' for i in range(count)]  # Дополнительные пути

        blocked = False
        for i in range(count):
            url = f'http://example.com{paths_extended[i % len(paths_extended)]}'
            path = paths_extended[i % len(paths_extended)]
            # Каждый запрос обрабатывается реальным движком защиты (status 404 — признак атаки)
            result = engine.check_and_record(ip, url, path, 'GET', 404, 'SimulatedAttackBot/1.0')
            if result['action'] == 'block':
                blocked = True
                break   # Остановка симуляции при обнаружении и блокировке

        stats = engine.get_ip_stats(ip)  # Финальная статистика симулированного IP
        return JsonResponse({
            'success': True,
            'ip': ip,
            'requests_sent': i + 1,
            'blocked': blocked,
            'stats': stats,
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


# =============================================================================
# БЛОК ОЧИСТКИ ДАННЫХ (ИНСТРУМЕНТ РАЗРАБОТКИ/ДЕМО)
# Полная очистка всех таблиц БД и in-memory трекеров.
# ВНИМАНИЕ: необратимая операция — все исторические данные удаляются.
# =============================================================================
@csrf_exempt
@require_http_methods(['POST'])
def api_clear_logs(request):
    """
    POST /waf/api/clear-logs/
    Очищает RequestLog, SecurityEvent, BlockedIP и сбрасывает все трекеры.
    Используется для сброса демо-данных перед показом.
    """
    try:
        RequestLog.objects.all().delete()       # Удаление всех логов запросов
        SecurityEvent.objects.all().delete()    # Удаление всех событий безопасности
        BlockedIP.objects.all().delete()        # Удаление всех блокировок

        # Сброс in-memory трекеров (скользящие окна в ProtectionEngine)
        engine = ProtectionEngine.get_instance()
        with engine._trackers_lock:
            engine._trackers.clear()   # Очистка всех IPTracker-объектов из памяти

        return JsonResponse({'success': True, 'message': 'Все логи очищены'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
