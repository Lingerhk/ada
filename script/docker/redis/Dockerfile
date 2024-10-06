
FROM redis:7.2.5

COPY redis/redis.conf /usr/local/etc/redis/redis.conf
COPY redis/ssl /usr/local/etc/redis/ssl

EXPOSE 5513
EXPOSE 6379

CMD [ "redis-server", "/usr/local/etc/redis/redis.conf" ]