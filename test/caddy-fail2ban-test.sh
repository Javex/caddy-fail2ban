#!/bin/bash

set -euo pipefail

fail2ban-server
sleep 1

output=$(curl http://127.0.0.1)
if [ "$output" != "ok" ]; then
  echo "Expected 'ok' output, got '${output}'"
  exit 1
fi

fail2ban-client set caddy_test banip 127.0.0.1

set +e
curl http://127.0.0.1
curl_exit_code=$?
set -e
if [ $curl_exit_code -eq 0 ]; then
  echo "Expected curl to exit with non-zero exit code, but it was successful";
  exit 1
fi

echo "Success!"
exit 0
