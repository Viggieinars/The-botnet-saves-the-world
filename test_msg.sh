#!/bin/bash

# Test script for MSG command
# Usage: Run this script and follow the prompts in each terminal

echo "=== MSG Command Test Instructions ==="
echo ""
echo "Terminal 1 (Server):"
echo "  ./tsamgroup14 5001"
echo ""
echo "Terminal 2 (Client 1):"
echo "  ./client 127.0.0.1 5001"
echo "  Then type: HELO,Group14"
echo ""
echo "Terminal 3 (Client 2):"
echo "  ./client 127.0.0.1 5001"
echo "  Then type: HELO,Group15"
echo ""
echo "Terminal 2 (Client 1) - Send message:"
echo "  MSG Group15 Hello from Group14!"
echo ""
echo "Terminal 3 should receive: Hello from Group14!"
echo ""
echo "=== Commands to Test ==="
echo "1. MSG <recipient> <message>  - Send message to another client by name"
echo "2. SENDMSG <groupID> <message> - (requires CLIENTAUTH first)"
echo "3. CONNECT <ip> <port> - (requires CLIENTAUTH first)"


