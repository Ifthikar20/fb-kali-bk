#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: ./create-org.sh <org-name> <admin-email> <target>"
    echo "Example: ./create-org.sh \"Acme Corp\" admin@acme.com example.com"
    exit 1
fi

ORG_NAME=$1
ADMIN_EMAIL=$2
TARGET=$3

echo "Creating organization: $ORG_NAME"

RESPONSE=$(curl -s -X POST http://localhost:8000/api/organizations \
  -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"$ORG_NAME\",
    \"admin_email\": \"$ADMIN_EMAIL\",
    \"allowed_targets\": [\"$TARGET\"]
  }")

echo "$RESPONSE" | python3 -m json.tool

API_KEY=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('api_key', ''))")
ELASTIC_IP=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('elastic_ip', ''))")

echo ""
echo "===================================="
echo "Organization Created!"
echo "===================================="
echo "API Key: $API_KEY"
echo "Attack IP: $ELASTIC_IP"
echo ""
echo "Save this API key!"
