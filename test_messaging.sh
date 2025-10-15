#!/bin/bash

# Test script for SENDMSG and GETMSG functionality
# This script sends test messages and retrieves them

echo "=== Testing SENDMSG and GETMSG ==="
echo ""
echo "Make sure your server is running with: ./tsamgroup14 4024"
echo ""
echo "Press Enter when your server is ready..."
read

# First, authenticate the client (your Group14isthebest command)
echo "Step 1: Authenticating client..."
echo "Group14isthebest" | nc 127.0.0.1 4024 &
sleep 1

# Connect to another server (you'll need to replace with actual IP/port)
echo ""
echo "Step 2: Connect to remote server (update IP/port in script if needed)"
echo "CONNECT 130.208.246.98 5001" | nc 127.0.0.1 4024 &
sleep 2

# Send a message to another group
echo ""
echo "Step 3: Sending a test message to Instr_1"
echo "SENDMSG Instr_1 Hello from Group 14!" | nc 127.0.0.1 4024
sleep 1

# Try to retrieve messages (should be empty initially)
echo ""
echo "Step 4: Retrieving messages (should be empty)"
echo "GETMSG" | nc 127.0.0.1 4024
sleep 1

echo ""
echo "=== Test complete ==="
echo "To properly test receiving messages, you need another server to send you a message."
echo "Check your server logs to see the message activity."

