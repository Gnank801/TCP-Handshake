# TCP Handshake Client

**Course:** CS425: Computer Networks  
**Instructor:** Adithya Vadapalli  
**TAs:** Mohan, Viren, Prakhar  

---

## Objective

This README explains the functionality of the client-side TCP three-way handshake implementation using raw sockets. The task was to construct and send raw TCP packets, manually mimicking the TCP connection initiation process, and correctly respond to the custom server implementation provided in the course repository.

---

## TCP Handshake Protocol Used

The server expects a simplified three-way handshake with specific sequence numbers:

1. **Client → Server:** SYN (sequence = 200)
2. **Server → Client:** SYN-ACK (sequence = 400, ack = 201)
3. **Client → Server:** ACK (sequence = 600, ack = 401)

---

## How the Code Works

### Dual Raw Sockets

- **Sending Socket:** Uses `IPPROTO_RAW` to construct and send custom IP + TCP headers.
- **Receiving Socket:** Uses `IPPROTO_TCP` to receive TCP packets from the server.

### Packet Construction

1. **IP Header**:
   - Source and destination IPs
   - Protocol: TCP
   - Total length: IP + TCP header size

2. **TCP Header**:
   - Source port: 54321
   - Destination port: 12345
   - Flags: SYN, ACK depending on the step
   - Sequence & acknowledgment numbers
   - Window size and checksum

3. **Checksum**:
   - Computed manually using a pseudo-header (required for TCP checksum).

### Handshake Logic

- Step 1: Send SYN packet (seq = 200)
- Step 2: Listen for SYN-ACK from server (seq = 400, ack = 201)
- Step 3: If correct, send ACK (seq = 600, ack = 401)

---

## How to Compile & Run

### 1. Compile the Client
```bash
g++ client.cpp -o client
```

### 2. Run the Server (in a separate terminal)
```bash
sudo ./server
```

### 3. Run the Client
```bash
sudo ./client
```

---

## Sample Output

### Client Terminal
```
[+] Sending SYN packet...
[+] Received SYN-ACK. Sending ACK...
[+] TCP Handshake complete!
```

### Server Terminal
```
[+] TCP Flags:  SYN: 1 ACK: 0 FIN: 0 ...
[+] Received SYN from 127.0.0.1
[+] Sent SYN-ACK
[+] TCP Flags:  SYN: 0 ACK: 1 FIN: 0 ...
[+] Received ACK, handshake complete.
```

---

## Notes & Tips

- **Run as root**: Raw sockets require administrative privileges.
- **Avoid kernel interference**:
```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```
- **Clean up rule**:
```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
```
- We need to be sure both client and server are using **localhost (127.0.0.1)**

---


## Contributions
- Banoth Mithun Raj(210258) - 34%
- Gude Rachana(210398) - 33%
- Kinjarapu Gnan(210520) - 33%
