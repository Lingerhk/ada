
FROM redis:7.2.5

USER root

COPY redis.conf /usr/local/etc/redis/redis.conf
COPY ssl /usr/local/etc/redis/ssl

RUN mkdir -p /data
RUN chown -R redis:redis /data

EXPOSE 9091
EXPOSE 6379

USER redis

CMD [ "redis-server", "/usr/local/etc/redis/redis.conf" ]