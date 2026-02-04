from rq import Worker, Queue, Connection
from redis import Redis

from server.config import settings


redis_conn = Redis.from_url(settings.redis_url)


if __name__ == "__main__":
    with Connection(redis_conn):
        worker = Worker([Queue("events")])
        worker.work()
