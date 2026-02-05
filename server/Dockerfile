FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY server/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

COPY server /srv/server
COPY server/alembic /srv/alembic
COPY server/alembic.ini /srv/alembic.ini
COPY server/entrypoint.sh /srv/entrypoint.sh

RUN chmod 755 /srv/entrypoint.sh \
    && addgroup --system app \
    && adduser --system --ingroup app --home /srv app \
    && chown -R app:app /srv

ENV PYTHONPATH=/srv

USER app

CMD ["/srv/entrypoint.sh"]
