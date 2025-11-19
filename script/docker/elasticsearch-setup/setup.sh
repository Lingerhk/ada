#!/bin/bash
set -e

# Determine Elasticsearch host (use localhost for host network, elasticsearch for bridge network)
ES_HOST="${ELASTICSEARCH_HOST:-elasticsearch}"
if [ "${ES_HOST}" = "localhost" ] || [ -z "$(getent hosts elasticsearch 2>/dev/null)" ]; then
    ES_HOST="localhost"
fi

# Determine Kibana host
KIBANA_HOST="${KIBANA_HOST:-kibana}"
if [ "${KIBANA_HOST}" = "localhost" ] || [ -z "$(getent hosts kibana 2>/dev/null)" ]; then
    KIBANA_HOST="localhost"
fi

# Password setup (skip if SKIP_PASSWORD_SETUP is set to true)
if [ "${SKIP_PASSWORD_SETUP}" != "true" ]; then
    # Wait for Elasticsearch to be ready
    echo "Waiting for Elasticsearch to be ready at ${ES_HOST}:9200..."
    until curl -s -u elastic:${ELASTIC_PASSWORD} http://${ES_HOST}:9200/_cluster/health > /dev/null; do
        echo "Elasticsearch is unavailable - sleeping"
        sleep 5
    done

    echo "Elasticsearch is up - setting up passwords"

    # Set kibana_system password
    echo "Setting kibana_system password..."
    curl -X POST -u elastic:${ELASTIC_PASSWORD} \
        "http://${ES_HOST}:9200/_security/user/kibana_system/_password" \
        -H "Content-Type: application/json" \
        -d "{\"password\": \"${KIBANA_PASSWORD}\"}"

    echo ""
    echo "Password setup completed successfully!"
else
    echo "Skipping password setup (SKIP_PASSWORD_SETUP=true)"
fi

# Optional: Wait for Kibana to be ready and create data views
if [ "${CREATE_DATA_VIEWS}" = "true" ]; then
    echo ""
    echo "Waiting for Kibana to be ready at ${KIBANA_HOST}:5601..."
    until curl -s -u elastic:${ELASTIC_PASSWORD} http://${KIBANA_HOST}:5601/api/status > /dev/null; do
        echo "Kibana is unavailable - sleeping"
        sleep 5
    done

    echo "Kibana is up - creating data views"

    # Create data view for winlog indices
    echo "Creating winlog-* data view..."
    curl -X POST -u elastic:${ELASTIC_PASSWORD} \
        "http://${KIBANA_HOST}:5601/api/data_views/data_view" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{
            "data_view": {
                "title": "ada-eventlog-*",
                "name": "Adaegis-WinEvent-Logs",
                "timeFieldName": "@timestamp",
                "allowNoIndex": true
            }
        }' || echo "Data view might already exist or Kibana not ready"

    # Create data view for flow indices
    echo "Creating flow-* data view..."
    curl -X POST -u elastic:${ELASTIC_PASSWORD} \
        "http://${KIBANA_HOST}:5601/api/data_views/data_view" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{
            "data_view": {
                "title": "ada-activity*",
                "name": "Adaegis-Activity-Alerts",
                "timeFieldName": "@timestamp",
                "allowNoIndex": true
            }
        }' || echo "Data view might already exist or Kibana not ready"

    # Create data view for zeek indices
    echo "Creating zeek-* data view..."
    curl -X POST -u elastic:${ELASTIC_PASSWORD} \
        "http://${KIBANA_HOST}:5601/api/data_views/data_view" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{
            "data_view": {
                "title": "ada-packetlog-*",
                "name": "Adaegis-Packet-Logs",
                "timeFieldName": "@timestamp",
                "allowNoIndex": true
            }
        }' || echo "Data view might already exist or Kibana not ready"

    echo ""
    echo "Data views created successfully!"
fi

echo ""
echo "Setup completed!"
