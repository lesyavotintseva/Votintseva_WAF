from django.apps import AppConfig


class WafConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'waf'
    verbose_name = 'WAF — Защита от форсированного браузинга'

    def ready(self):
        from waf.protection import ProtectionEngine
        ProtectionEngine.get_instance()
