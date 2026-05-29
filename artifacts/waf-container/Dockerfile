FROM python:3.11-slim

LABEL maintainer="WAF Container — Forced Browsing Protection"
LABEL description="Контейнер защиты от атаки форсированного веб-браузинга (УБИ.159)"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput

EXPOSE 8000

ENV DJANGO_SETTINGS_MODULE=waf_project.settings
ENV DEBUG=False

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/waf/ || exit 1

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
