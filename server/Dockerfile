FROM python:3.11-slim

WORKDIR /srv

# deps
COPY server/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

# app code
COPY server /srv/server

# alembic
COPY server/alembic /srv/alembic
COPY server/alembic.ini /srv/alembic.ini

# entrypoint
COPY server/entrypoint.sh /srv/entrypoint.sh
RUN chmod +x /srv/entrypoint.sh

ENV PYTHONPATH=/srv

CMD ["/srv/entrypoint.sh"]
