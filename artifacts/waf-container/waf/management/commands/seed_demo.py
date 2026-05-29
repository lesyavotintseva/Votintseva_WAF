"""
Команда для заполнения демо-данными.
Использование: python manage.py seed_demo
"""
import random
import datetime
from django.core.management.base import BaseCommand
from django.utils import timezone
from waf.models import BlockedIP, SecurityEvent, RequestLog


SAMPLE_IPS = [
    '185.220.101.45', '91.108.4.0', '45.142.212.100',
    '198.51.100.23', '203.0.113.42', '192.168.10.55',
    '10.0.0.120', '172.16.5.200', '8.8.8.8',
]

SAMPLE_URLS = [
    '/admin/', '/wp-admin/', '/backup.zip', '/.env', '/config.php',
    '/api/v1/users', '/api/v1/admin', '/shell.php', '/.git/config',
    '/phpmyadmin/', '/wp-config.php', '/etc/passwd', '/private/',
    '/uploads/shell.php', '/api/v2/tokens', '/dashboard/admin',
    '/secret/', '/manage/', '/console/', '/db/', '/logs/',
    '/api/v1/secrets', '/backup.sql', '/.htaccess', '/info.php',
]

EVENT_TYPES = [
    ('attack_detected', 60),
    ('blocked_request', 100),
    ('ip_blocked', 15),
    ('threshold_warning', 30),
    ('ip_unblocked', 5),
]


class Command(BaseCommand):
    help = 'Заполнить базу данных демо-данными для визуализации'

    def add_arguments(self, parser):
        parser.add_argument('--requests', type=int, default=500, help='Количество запросов')
        parser.add_argument('--events', type=int, default=150, help='Количество событий')
        parser.add_argument('--blocks', type=int, default=8, help='Количество блокировок')

    def handle(self, *args, **options):
        now = timezone.now()

        self.stdout.write('Создаю записи запросов...')
        logs = []
        for i in range(options['requests']):
            ts = now - datetime.timedelta(
                hours=random.uniform(0, 23),
                minutes=random.uniform(0, 59)
            )
            ip = random.choice(SAMPLE_IPS)
            was_blocked = random.random() < 0.25
            status = 403 if was_blocked else random.choice([200, 200, 200, 404, 404, 301, 500])
            logs.append(RequestLog(
                timestamp=ts,
                source_ip=ip,
                method=random.choice(['GET', 'GET', 'GET', 'POST']),
                url='http://example.com' + random.choice(SAMPLE_URLS),
                status_code=status,
                user_agent=random.choice([
                    'Mozilla/5.0 (compatible; DirBuster)',
                    'gobuster/3.1.0',
                    'nikto/2.1.6',
                    'Mozilla/5.0 (Windows NT 10.0)',
                    'sqlmap/1.7',
                ]),
                was_blocked=was_blocked,
                response_time_ms=random.uniform(5, 300),
            ))
        RequestLog.objects.bulk_create(logs, ignore_conflicts=True)
        self.stdout.write(self.style.SUCCESS(f'  Создано {len(logs)} записей запросов'))

        self.stdout.write('Создаю события безопасности...')
        events = []
        weighted = []
        for etype, weight in EVENT_TYPES:
            weighted.extend([etype] * weight)

        for i in range(options['events']):
            ts = now - datetime.timedelta(
                hours=random.uniform(0, 23),
                minutes=random.uniform(0, 59)
            )
            ip = random.choice(SAMPLE_IPS)
            etype = random.choice(weighted)
            unique_urls = random.randint(10, 80)
            events.append(SecurityEvent(
                timestamp=ts,
                event_type=etype,
                source_ip=ip,
                url='http://example.com' + random.choice(SAMPLE_URLS),
                method=random.choice(['GET', 'POST']),
                status_code=random.choice([403, 404, 200, 500]),
                user_agent='DirBuster/1.0',
                unique_urls_at_time=unique_urls,
                requests_in_window=random.randint(unique_urls, unique_urls + 30),
                error_rate=random.uniform(40, 100),
                details={'reason': random.choice(['unique_url_limit', 'error_rate_limit'])},
            ))
        SecurityEvent.objects.bulk_create(events, ignore_conflicts=True)
        self.stdout.write(self.style.SUCCESS(f'  Создано {len(events)} событий'))

        self.stdout.write('Создаю блокировки...')
        attacking_ips = random.sample(SAMPLE_IPS, min(options['blocks'], len(SAMPLE_IPS)))
        for ip in attacking_ips:
            expires = now + datetime.timedelta(hours=random.randint(1, 24))
            BlockedIP.objects.update_or_create(
                ip_address=ip,
                defaults={
                    'is_active': True,
                    'reason': random.choice(['unique_url_limit', 'error_rate_limit', 'rps_limit']),
                    'blocked_at': now - datetime.timedelta(minutes=random.randint(5, 120)),
                    'expires_at': expires,
                    'unique_urls_count': random.randint(50, 200),
                    'total_requests': random.randint(100, 500),
                    'error_404_count': random.randint(50, 300),
                }
            )
        self.stdout.write(self.style.SUCCESS(f'  Создано {len(attacking_ips)} блокировок'))

        self.stdout.write(self.style.SUCCESS('\nДемо-данные успешно загружены!'))
        self.stdout.write('  Откройте /waf/ для просмотра дашборда')
