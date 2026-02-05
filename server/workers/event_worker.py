from redis import Redis
from rq import Connection, Queue, Worker

from server.config import settings

redis_conn = Redis.from_url(settings.redis_url)


if __name__ == "__main__":
    with Connection(redis_conn):
        worker = Worker([Queue("events")])
        worker.work()
