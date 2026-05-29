import json
import logging
import traceback
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        if hasattr(record, 'extra'):
            log_entry.update(record.extra)
        if record.exc_info:
            log_entry['exception'] = traceback.format_exception(*record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


security_logger = logging.getLogger('waf.security')


def log_event(event_type: str, ip: str, url: str = '', **kwargs):
    extra = {
        'event_type': event_type,
        'source_ip': ip,
        'url': url,
        **kwargs,
    }
    security_logger.info(
        f'{event_type}: {ip} -> {url}',
        extra={'extra': extra}
    )
