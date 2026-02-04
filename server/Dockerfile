FROM python:3.11-slim

WORKDIR /srv
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt
COPY server /srv/server
COPY alembic /srv/alembic
COPY alembic.ini /srv/alembic.ini
ENV PYTHONPATH=/srv

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
