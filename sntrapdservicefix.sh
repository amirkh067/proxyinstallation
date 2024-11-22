#!/bin/bash

# Enable snmptrapd to start on boot by creating a symlink
echo "Enabling snmptrapd to start on boot..."

SERVICE_FILE="/lib/systemd/system/snmptrapd.service"
TARGET_DIR="/etc/systemd/system/multi-user.target.wants/"
SYMLINK="${TARGET_DIR}snmptrapd.service"

# Check if the service file exists
if [ ! -f "$SERVICE_FILE" ]; then
  echo "Error: snmptrapd.service file not found at $SERVICE_FILE"
  exit 1
fi

# Create symlink if it does not already exist
if [ -L "$SYMLINK" ]; then
  echo "snmptrapd is already enabled to start on boot."
else
  ln -s "$SERVICE_FILE" "$SYMLINK"
  echo "Symlink created to enable snmptrapd on boot."
fi

# Reload systemd and start the service
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Starting snmptrapd service..."
systemctl start snmptrapd

# Check status
if systemctl is-active --quiet snmptrapd; then
  echo "snmptrapd is now running and enabled to start on boot."
else
  echo "Failed to start snmptrapd. Check the service status for more details."
fi
