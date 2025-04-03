#!/bin/sh
set -e

# create necessary directories with proper permissions
mkdir -p /run/clamav && chown clamav:clamav /run/clamav && chmod 750 /run/clamav
mkdir -p /var/lib/clamav
chown -R clamav:clamav /job

# start freshclam in the background
/usr/bin/freshclam --daemon &
sleep 21  # Wait for definitions to update

# start clamd in the background
/usr/sbin/clamd &
sleep 21
# start analyzer script
exec python ClamAV/pyclam_analyzer.py
