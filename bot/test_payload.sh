#!/bin/sh
echo "PAYLOAD_EXECUTED $(date) $(hostname) $(whoami)" > /tmp/.test_payload_marker
echo "test payload ran"
