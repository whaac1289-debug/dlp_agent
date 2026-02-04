FROM python:3.11-slim

WORKDIR /srv
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt
COPY server /srv/server
COPY alembic /srv/alembic
COPY alembic.ini /srv/alembic.ini
COPY server/entrypoint.sh /srv/entrypoint.sh
ENV PYTHONPATH=/srv

RUN chmod +x /srv/entrypoint.sh
CMD ["/srv/entrypoint.sh"]
