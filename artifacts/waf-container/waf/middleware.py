# =============================================================================
# БЛОК ИМПОРТА ЗАВИСИМОСТЕЙ
# =============================================================================
import time
import logging
import requests as req_lib          # HTTP-клиент для проксирования запросов на backend
from django.http import HttpResponse, JsonResponse
from django.conf import settings

logger = logging.getLogger('waf')


# =============================================================================
# БЛОК ИЗВЛЕЧЕНИЯ IP-АДРЕСА КЛИЕНТА
# Учитывает заголовок X-Forwarded-For при работе за обратным прокси (nginx, LB).
# =============================================================================
def get_client_ip(request) -> str:
    """
    Извлекает реальный IP клиента из запроса.
    X-Forwarded-For может содержать цепочку прокси: берём первый (оригинальный) IP.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()  # Первый IP — исходный клиент
    return request.META.get('REMOTE_ADDR', '127.0.0.1')  # Прямое соединение


# =============================================================================
# БЛОК DJANGO MIDDLEWARE — ТОЧКА ПЕРЕХВАТА ВСЕХ ЗАПРОСОВ
# Middleware вызывается для каждого HTTP-запроса до передачи в view-функцию.
# Порядок в settings.py определяет очерёдность выполнения.
# =============================================================================
class ForcedBrowsingProtectionMiddleware:
    def __init__(self, get_response):
        """
        Вызывается однократно при старте Django.
        get_response — следующий обработчик в цепочке middleware.
        """
        self.get_response = get_response

    def __call__(self, request):
        """
        Вызывается для каждого входящего запроса.
        Реализует паттерн "Chain of Responsibility": pass → analyze → block/proxy.
        """
        # БЛОК ПОЛУЧЕНИЯ КОНФИГА И БАЗОВЫХ ПАРАМЕТРОВ ЗАПРОСА
        from waf.protection import ProtectionEngine
        engine = ProtectionEngine.get_instance()   # Singleton движка защиты

        path = request.path
        excluded = engine.config.get('excluded_paths', [])

        # Системные пути (/waf/, /admin/, /static/) — пропускаем без анализа
        if any(path.startswith(e) for e in excluded):
            return self.get_response(request)

        ip = get_client_ip(request)           # Реальный IP источника запроса
        backend_url = engine.config.get('backend_url', '').rstrip('/')
        url = request.build_absolute_uri()    # Полный URL запроса
        method = request.method               # HTTP-метод (GET, POST и т.д.)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # БЛОК ПРЕДВАРИТЕЛЬНОЙ ПРОВЕРКИ БЛОКИРОВКИ
        # Быстрая проверка до обращения к backend — экономия ресурсов
        if engine.is_blocked(ip):
            self._save_request_log(ip, method, url, 403, user_agent, blocked=True)
            return self._blocked_response(engine)  # Возврат 403 без обращения к backend

        # БЛОК DEMO-РЕЖИМА (без backend)
        # Если backend_url пустой — запрос обрабатывается самим Django
        if not backend_url:
            response = self.get_response(request)   # Django обрабатывает запрос локально
            status_code = response.status_code
            # Анализ запроса уже после получения ответа (знаем статус код)
            check_result = engine.check_and_record(ip, url, path, method, status_code, user_agent)
            self._save_request_log(ip, method, url, status_code, user_agent,
                                    blocked=(check_result['action'] == 'block'))
            if check_result['action'] == 'block':
                return self._blocked_response(engine)
            return response

        # БЛОК ПРОКСИРОВАНИЯ НА BACKEND (production-режим)
        start_ts = time.time()  # Засекаем время для метрики response_time_ms
        try:
            proxy_resp = self._proxy_request(request, backend_url)  # HTTP-запрос к backend
            elapsed = (time.time() - start_ts) * 1000  # Время ответа в миллисекундах
            status_code = proxy_resp.status_code        # Статус ответа backend (важен для 404-анализа)
        except Exception as e:
            logger.error('Proxy error for %s %s: %s', method, url, e)
            status_code = None
            elapsed = None
            proxy_resp = None

        # БЛОК АНАЛИЗА И ПРИНЯТИЯ РЕШЕНИЯ
        # Выполняется ПОСЛЕ получения ответа от backend — анализируем реальный status_code
        check_result = engine.check_and_record(ip, url, path, method, status_code, user_agent)
        is_blocked = check_result['action'] == 'block'
        self._save_request_log(ip, method, url, status_code, user_agent,
                                blocked=is_blocked, elapsed=elapsed)

        if is_blocked:
            return self._blocked_response(engine)   # IP превысил порог — блокируем

        # БЛОК ФОРМИРОВАНИЯ ОТВЕТА КЛИЕНТУ
        if proxy_resp is not None:
            return self._build_django_response(proxy_resp)  # Прокси-ответ → Django HttpResponse

        return HttpResponse('Bad Gateway', status=502)  # Backend недоступен

    # -------------------------------------------------------------------------
    # БЛОК ОТПРАВКИ ЗАПРОСА НА BACKEND (HTTP-ПРОКСИ)
    # -------------------------------------------------------------------------
    def _proxy_request(self, request, backend_url: str):
        """
        Пересылает оригинальный запрос на защищаемый backend.
        Копирует заголовки, метод, тело запроса. Добавляет X-Forwarded-For.
        """
        target_url = backend_url + request.get_full_path()

        # Преобразование META-заголовков Django в стандартные HTTP-заголовки
        # META-ключи вида HTTP_ACCEPT → заголовок Accept
        headers = {
            key[5:].replace('_', '-').title(): value
            for key, value in request.META.items()
            if key.startswith('HTTP_') and key not in ('HTTP_HOST',)
        }
        headers['X-Forwarded-For'] = get_client_ip(request)   # Передаём реальный IP
        headers['X-Forwarded-Proto'] = request.scheme          # Передаём протокол (http/https)

        # Тело запроса передаём только для методов с payload
        body = request.body if request.method in ('POST', 'PUT', 'PATCH') else None

        resp = req_lib.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=body,
            allow_redirects=False,  # Редиректы возвращаем клиенту как есть (3xx)
            timeout=30,             # Таймаут 30 сек — защита от зависшего backend
            verify=False,           # SSL-верификация отключена для внутренних сетей
        )
        return resp

    # -------------------------------------------------------------------------
    # БЛОК ПРЕОБРАЗОВАНИЯ ОТВЕТА BACKEND В DJANGO HTTP-RESPONSE
    # -------------------------------------------------------------------------
    def _build_django_response(self, proxy_resp) -> HttpResponse:
        """
        Конвертирует ответ библиотеки requests в Django HttpResponse.
        Исключает заголовки, несовместимые с Django/WSGI.
        """
        excluded_headers = {
            'transfer-encoding', 'content-encoding',  # Django управляет сжатием сам
            'connection', 'keep-alive',                # Управление соединением — на стороне WSGI
            'proxy-authenticate',
        }
        response = HttpResponse(
            content=proxy_resp.content,
            status=proxy_resp.status_code,
            content_type=proxy_resp.headers.get('content-type', 'text/html'),
        )
        # Копируем допустимые заголовки backend-а клиенту
        for header, value in proxy_resp.headers.items():
            if header.lower() not in excluded_headers:
                response[header] = value
        return response

    # -------------------------------------------------------------------------
    # БЛОК ФОРМИРОВАНИЯ ОТВЕТА ПРИ БЛОКИРОВКЕ (403 Forbidden)
    # -------------------------------------------------------------------------
    def _blocked_response(self, engine) -> HttpResponse:
        """
        Возвращает HTML-страницу блокировки (или JSON для API-клиентов).
        HTTP-код 403 (или настроенный в response_codes.blocked).
        """
        blocked_code = engine.config.get('response_codes', {}).get('blocked', 403)
        accept = ''
        if hasattr(self, '_current_request'):
            accept = self._current_request.META.get('HTTP_ACCEPT', '')
        if 'application/json' in accept:
            # API-клиенты получают JSON-ошибку
            return JsonResponse(
                {'error': 'Forbidden',
                 'message': 'Доступ заблокирован системой защиты от форсированного веб-браузинга.'},
                status=blocked_code
            )
        # Браузеры получают HTML-страницу с объяснением
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Доступ заблокирован</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
  .box {{ background: #1e293b; border: 1px solid #ef4444; border-radius: 12px;
          padding: 3rem; max-width: 480px; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,.5); }}
  .icon {{ font-size: 4rem; margin-bottom: 1rem; }}
  h1 {{ color: #ef4444; margin: 0 0 .5rem; font-size: 1.75rem; }}
  p {{ color: #94a3b8; line-height: 1.6; }}
  .code {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px;
           padding: .5rem 1rem; display: inline-block; font-family: monospace;
           font-size: 1.25rem; color: #ef4444; margin: 1rem 0; }}
</style>
</head>
<body>
<div class="box">
  <div class="icon">🛡️</div>
  <h1>Доступ заблокирован</h1>
  <div class="code">{blocked_code} Forbidden</div>
  <p>Ваш IP-адрес заблокирован системой защиты от форсированного веб-браузинга.</p>
  <p>Если вы считаете, что блокировка произошла ошибочно, обратитесь к администратору.</p>
</div>
</body>
</html>"""
        return HttpResponse(html, status=blocked_code, content_type='text/html; charset=utf-8')

    # -------------------------------------------------------------------------
    # БЛОК ЗАПИСИ В ЛОГ ЗАПРОСОВ (RequestLog)
    # -------------------------------------------------------------------------
    def _save_request_log(self, ip, method, url, status_code, user_agent,
                           blocked=False, elapsed=None):
        """
        Персистентная запись каждого запроса в SQLite.
        URL и User-Agent усекаются во избежание переполнения БД.
        Ошибки записи не прерывают обработку запроса (try/except).
        """
        try:
            from waf.models import RequestLog
            RequestLog.objects.create(
                source_ip=ip,
                method=method,
                url=url[:2048],          # Ограничение длины URL
                status_code=status_code,
                user_agent=user_agent[:512],  # Ограничение длины User-Agent
                was_blocked=blocked,
                response_time_ms=elapsed,
            )
        except Exception as e:
            logger.error('Ошибка записи лога запроса: %s', e)
