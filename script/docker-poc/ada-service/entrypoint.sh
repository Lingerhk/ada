#!/bin/bash

CONFIG_FILE="/home/adadmin/conf/easytier.toml"

# Function to resolve domain to IP
resolve_domain() {
    local domain="$1"
    local ip=""

    # Try getent first
    ip=$(getent hosts "$domain" 2>/dev/null | awk '{print $1}' | head -n1)

    # Fallback to dig
    if [ -z "$ip" ]; then
        ip=$(dig +short "$domain" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
    fi

    # Fallback to nslookup
    if [ -z "$ip" ]; then
        ip=$(nslookup "$domain" 2>/dev/null | awk '/^Address: / { print $2 }' | head -n1)
    fi

    echo "$ip"
}

# Resolve hardcoded domains
MONGODB_DOMAIN="ada-poc-db-mongodb.ns-x7n5f7v4.svc"
REDIS_DOMAIN="ada-poc-redis-redis.ns-x7n5f7v4.svc"

echo "Resolving domain names for easytier.toml..."

# Resolve MongoDB
echo "Resolving: $MONGODB_DOMAIN"
MONGODB_IP=$(resolve_domain "$MONGODB_DOMAIN")
if [ -n "$MONGODB_IP" ]; then
    echo "  -> Resolved to: $MONGODB_IP"
    sed -i "s|${MONGODB_DOMAIN}|${MONGODB_IP}|g" "$CONFIG_FILE"
else
    echo "  -> WARNING: Could not resolve $MONGODB_DOMAIN"
fi

# Resolve Redis
echo "Resolving: $REDIS_DOMAIN"
REDIS_IP=$(resolve_domain "$REDIS_DOMAIN")
if [ -n "$REDIS_IP" ]; then
    echo "  -> Resolved to: $REDIS_IP"
    sed -i "s|${REDIS_DOMAIN}|${REDIS_IP}|g" "$CONFIG_FILE"
else
    echo "  -> WARNING: Could not resolve $REDIS_DOMAIN"
fi

echo "Domain resolution complete."

# Ensure logs directory is writable at runtime (bind mounts override image ownership)
mkdir -p /home/adadmin/logs
chown -R adadmin:root /home/adadmin/logs || true
chmod 775 /home/adadmin/logs || true

# Start supervisord
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
