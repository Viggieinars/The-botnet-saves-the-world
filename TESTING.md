# Testing SENDMSG and GETMSG

## Setup

1. **Compile the code:**
   ```bash
   make
   ```

2. **Start your server:**
   ```bash
   ./tsamgroup14 4024
   ```

3. **In another terminal, start your client:**
   ```bash
   ./client 127.0.0.1 4024
   ```

## Test Scenarios

### Test 1: Authenticate Client
In the client terminal, type:
```
Group14isthebest
```
✓ This registers your client with the server so it can send commands.

### Test 2: List Connected Servers
In the client terminal, type:
```
LISTSERVERS
```
✓ Should show which servers you're connected to (initially none).

### Test 3: Connect to Another Server
In the client terminal, type:
```
CONNECT 130.208.246.98 5001
```
✓ This connects to the instructor server.
✓ Check server logs - should see "Connection established" and "sent HELO"

### Test 4: Send a Message
Once connected to another server, send a message:
```
SENDMSG Instr_1 Hello, this is a test message!
```
✓ Check server logs - should see "Sent message to Instr_1"

### Test 5: Receive Messages (requires another server to send to you)
Ask another group or use the instructor server to send you a message.
The format they should use:
```
SENDMSG,A5_14,<their_group_id>,Test message content
```

When a message arrives, your server logs will show:
```
Received and stored message from <group>: <message> (total messages: X)
```

### Test 6: Retrieve Messages
In the client terminal, type:
```
GETMSG
```
✓ If messages are available: displays "FROM:<group> MSG:<content>"
✓ If no messages: displays "No messages available"

### Test 7: Multiple Messages
Send multiple messages and retrieve them one by one with GETMSG.
Each GETMSG retrieves the oldest message first (FIFO queue).

## Simulating Message Receipt (for testing without another server)

You can manually inject a message into your server by connecting with netcat:

1. In a new terminal:
   ```bash
   nc 127.0.0.1 4024
   ```

2. Manually send a formatted SENDMSG (remember the message format!):
   Format: `<SOH><length><STX>SENDMSG,A5_14,TestGroup,Hello!<ETX>`
   
   This is complex to type manually, but your client should format it automatically.

## Expected Server Log Output

Successful message flow should show:
```
Connection established to 130.208.246.98:5001, sent HELO
Received command: HELO,Instr_1
Sent SERVERS to Instr_1: SERVERS,A5_14,130.208.246.98,4024;
Sent message to Instr_1: Hello, this is a test message!
Received and stored message from Instr_1: Reply message (total messages: 1)
Client retrieved message from Instr_1 (remaining: 0)
```

## Common Issues

1. **"Client closed connection" immediately** - FIXED (non-blocking socket issue)
2. **Messages not stored** - Check that the sender is using the correct format
3. **Can't send messages** - Make sure you authenticated with "Group14isthebest" first
4. **No connection** - Verify the remote server IP and port are correct

