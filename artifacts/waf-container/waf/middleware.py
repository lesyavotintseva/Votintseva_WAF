import time
import logging
import requests as req_lib
from django.http import HttpResponse, JsonResponse
from django.conf import settings

logger = logging.getLogger('waf')


def get_client_ip(request) -> str:
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


class ForcedBrowsingProtectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from waf.protection import ProtectionEngine
        engine = ProtectionEngine.get_instance()

        path = request.path
        excluded = engine.config.get('excluded_paths', [])
        if any(path.startswith(e) for e in excluded):
            return self.get_response(request)

        ip = get_client_ip(request)
        backend_url = engine.config.get('backend_url', '').rstrip('/')
        url = request.build_absolute_uri()
        method = request.method
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        if engine.is_blocked(ip):
            self._save_request_log(ip, method, url, 403, user_agent, blocked=True)
            return self._blocked_response(engine)

        if not backend_url:
            response = self.get_response(request)
            status_code = response.status_code
            check_result = engine.check_and_record(ip, url, path, method, status_code, user_agent)
            self._save_request_log(ip, method, url, status_code, user_agent,
                                    blocked=(check_result['action'] == 'block'))
            if check_result['action'] == 'block':
                return self._blocked_response(engine)
            return response

        start_ts = time.time()
        try:
            proxy_resp = self._proxy_request(request, backend_url)
            elapsed = (time.time() - start_ts) * 1000
            status_code = proxy_resp.status_code
        except Exception as e:
            logger.error('Proxy error for %s %s: %s', method, url, e)
            status_code = None
            elapsed = None
            proxy_resp = None

        check_result = engine.check_and_record(ip, url, path, method, status_code, user_agent)
        is_blocked = check_result['action'] == 'block'
        self._save_request_log(ip, method, url, status_code, user_agent,
                                blocked=is_blocked, elapsed=elapsed)

        if is_blocked:
            return self._blocked_response(engine)

        if proxy_resp is not None:
            return self._build_django_response(proxy_resp)

        return HttpResponse('Bad Gateway', status=502)

    def _proxy_request(self, request, backend_url: str):
        target_url = backend_url + request.get_full_path()
        headers = {
            key[5:].replace('_', '-').title(): value
            for key, value in request.META.items()
            if key.startswith('HTTP_') and key not in ('HTTP_HOST',)
        }
        headers['X-Forwarded-For'] = get_client_ip(request)
        headers['X-Forwarded-Proto'] = request.scheme
        body = request.body if request.method in ('POST', 'PUT', 'PATCH') else None
        resp = req_lib.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=body,
            allow_redirects=False,
            timeout=30,
            verify=False,
        )
        return resp

    def _build_django_response(self, proxy_resp) -> HttpResponse:
        excluded_headers = {
            'transfer-encoding', 'content-encoding',
            'connection', 'keep-alive', 'proxy-authenticate',
        }
        response = HttpResponse(
            content=proxy_resp.content,
            status=proxy_resp.status_code,
            content_type=proxy_resp.headers.get('content-type', 'text/html'),
        )
        for header, value in proxy_resp.headers.items():
            if header.lower() not in excluded_headers:
                response[header] = value
        return response

    def _blocked_response(self, engine) -> HttpResponse:
        blocked_code = engine.config.get('response_codes', {}).get('blocked', 403)
        accept = ''
        if hasattr(self, '_current_request'):
            accept = self._current_request.META.get('HTTP_ACCEPT', '')
        if 'application/json' in accept:
            return JsonResponse(
                {'error': 'Forbidden', 'message': 'Доступ заблокирован системой защиты от форсированного веб-браузинга.'},
                status=blocked_code
            )
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

    def _save_request_log(self, ip, method, url, status_code, user_agent,
                           blocked=False, elapsed=None):
        try:
            from waf.models import RequestLog
            RequestLog.objects.create(
                source_ip=ip,
                method=method,
                url=url[:2048],
                status_code=status_code,
                user_agent=user_agent[:512],
                was_blocked=blocked,
                response_time_ms=elapsed,
            )
        except Exception as e:
            logger.error('Ошибка записи лога запроса: %s', e)
