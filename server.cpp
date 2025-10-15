#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>

#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <list>
#include <algorithm>
#include <time.h>

#define BACKLOG 5

int client_sock = -1;  // Initialize to invalid socket
std::string myGroupID = "A5_14";

// Client info
class Client {
public:
    int sock;
    std::string name;
    std::string ip;
    int port;

    Client(int socket, std::string ipAddr, int portNumber) : sock(socket), ip(ipAddr), port(portNumber) {}
    ~Client() {}
};

//recieve message 
//keep alive
//get message

// ---------------------------------------------------------------------------
// KEEPALIVE implementation notes
// We periodically send a framed payload to each directly connected peer:
//   KEEPALIVE,<No. of Messages>
// where <No. of Messages> is the number of messages we currently hold that are
// destined for that peer. We must not send more than once per minute.
// ---------------------------------------------------------------------------

// Track the last time we SENT a KEEPALIVE to each socket (rate limiting)
static std::map<int, time_t> lastKeepaliveSentAt;

// Track the last time we RECEIVED a KEEPALIVE from each socket (for observability)
static std::map<int, time_t> lastKeepaliveReceivedAt;

// (moved KEEPALIVE helpers below to ensure visibility of symbols they depend on)

std::map<int, Client*> clients;

// Helper to set non-blocking
void setNonBlocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

void sendFormattedMessage(int sock, const std::string& msg) {
    uint16_t len = msg.length() + 5;
    char sendbuf[1024];
    sendbuf[0] = 0x01;
    uint16_t len_n = htons(len);
    memcpy(&sendbuf[1], &len_n, 2);
    sendbuf[3] = 0x02;
    memcpy(&sendbuf[4], msg.c_str(), msg.length());
    sendbuf[4 + msg.length()] = 0x03;
    send(sock, sendbuf, len, 0);
}

// ---------------------------------------------------------------------------
// KEEPALIVE helpers (placed here so they can use 'clients' and sendFormattedMessage)
// ---------------------------------------------------------------------------

// Placeholder hook to obtain the number of pending messages for a specific peer.
// NOTE: Your teammate implementing GETMSGS/SENDMSGS should replace this with
// a real lookup against the pending message store keyed by the peer's group id.
static unsigned int getPendingCountForPeer(const Client* peer)
{
    (void)peer; // silence unused-parameter until message queue logic is added
    // TODO: replace with actual count of messages waiting for 'peer->name'
    // Example once implemented: return pendingMessagesByGroup[peer->name].size();
    return 0;
}

// Send a single KEEPALIVE to 'peerSock' if at least 60s have elapsed since last send.
static void maybeSendKeepalive(int peerSock)
{
    time_t now = time(nullptr);

    // Enforce: do not send more than once per minute per peer
    auto it = lastKeepaliveSentAt.find(peerSock);
    if (it != lastKeepaliveSentAt.end())
    {
        if (difftime(now, it->second) < 60.0)
        {
            return; // Too soon to send another KEEPALIVE
        }
    }

    // Find 'peerSock' in our clients map to compute the pending count for that peer
    auto cIt = clients.find(peerSock);
    if (cIt == clients.end() || cIt->second == nullptr)
    {
        return; // Unknown or already closed
    }

    const Client* peer = cIt->second;
    unsigned int pendingCount = getPendingCountForPeer(peer);

    // Compose the payload in the required format: KEEPALIVE,<No. of Messages>
    std::ostringstream payload;
    payload << "KEEPALIVE," << pendingCount;

    // Send framed using our helper
    sendFormattedMessage(peerSock, payload.str());

    // Record the send time for rate limiting
    lastKeepaliveSentAt[peerSock] = now;
}

std::string getLocalIPAddress() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return "127.0.0.1";

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("8.8.8.8");
    dest.sin_port = htons(80);

    connect(sock, (struct sockaddr*)&dest, sizeof(dest));

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr*)&name, &namelen);

    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &name.sin_addr, buffer, sizeof(buffer));

    close(sock);
    return std::string(buffer);
}


// Open server socket
int open_socket(int portno) {
    int sock;
    int set = 1;
    struct sockaddr_in sk_addr;

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Failed to open socket");
        return -1;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0) {
        perror("Failed to set SO_REUSEADDR");
    }

    setNonBlocking(sock);

    memset(&sk_addr, 0, sizeof(sk_addr));
    sk_addr.sin_family = AF_INET;
    sk_addr.sin_addr.s_addr = INADDR_ANY;
    sk_addr.sin_port = htons(portno);

    if(bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0) {
        perror("Failed to bind to socket");
        return -1;
    }

    return sock;
}

// Close client connection and cleanup pollfds + clients
void closeClient(int clientSocket, std::vector<struct pollfd> &pollfds) {
    std::cout << "Client closed connection: " << clientSocket << std::endl;
    close(clientSocket);
    clients.erase(clientSocket);

    pollfds.erase(std::remove_if(pollfds.begin(), pollfds.end(),
        [clientSocket](struct pollfd &p) { return p.fd == clientSocket; }),
        pollfds.end());
}

// Create formatted message
// Format: <SOH><length><STX><payload><ETX>
std::string createMessage(const std::string &payload) {
    std::string msg;
    uint16_t total_length = 5 + payload.length(); // SOH + length(2) + STX + payload + ETX
    
    msg += (char)0x01; // SOH
    
    // Add length in network byte order
    uint16_t net_length = htons(total_length);
    msg.append((char*)&net_length, 2);
    
    msg += (char)0x02; // STX
    msg += payload;
    msg += (char)0x03; // ETX
    
    return msg;
}

// Parse formatted message and extract payload
// Format: <SOH><length><STX><payload><ETX>
// Returns true if valid, false otherwise
bool parseMessage(const char* buffer, int bufferLen, std::string &payload) {
    if (bufferLen < 5) {
        std::cerr << "Message too short" << std::endl;
        return false;
    }

    // Check SOH (Start of Header)
    if ((unsigned char)buffer[0] != 0x01) {
        std::cerr << "Invalid SOH" << std::endl;
        return false;
    }

    // Extract length (2 bytes in network byte order)
    uint16_t total_length;
    memcpy(&total_length, &buffer[1], 2);
    total_length = ntohs(total_length);

    // Verify we received the complete message
    if (bufferLen < total_length) {
        std::cerr << "Incomplete message: expected " << total_length 
                  << " bytes, got " << bufferLen << std::endl;
        return false;
    }

    // Check STX (Start of Text)
    if ((unsigned char)buffer[3] != 0x02) {
        std::cerr << "Invalid STX" << std::endl;
        return false;
    }

    // Check ETX (End of Text)
    if ((unsigned char)buffer[total_length - 1] != 0x03) {
        std::cerr << "Invalid ETX" << std::endl;
        return false;
    }

    // Extract payload (between STX and ETX)
    int payload_length = total_length - 5; // total - (SOH + length + STX + ETX)
    if (payload_length > 0) {
        payload.assign(&buffer[4], payload_length);
    } else {
        payload.clear();
    }

    return true;
}

// Handle client commands
void clientCommand(int clientSocket, char *buffer, std::vector<struct pollfd> &pollfds, int port) {
    std::vector<std::string> tokens;
    std::stringstream stream(buffer);
    std::string token;

    while(stream >> token) tokens.push_back(token);

    if(tokens.empty()) return;

    if(tokens[0] == "CONNECT" && tokens.size() == 3 && clientSocket == client_sock) {
        std::string ip = tokens[1];
        int port = std::stoi(tokens[2]);

        int outSock = socket(AF_INET, SOCK_STREAM, 0);
        if(outSock < 0) {
            perror("Failed to create outgoing socket");
            return;
        }

        setNonBlocking(outSock);

        struct sockaddr_in serverAddr;
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);

        if(inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr) <= 0) {
            std::cerr << "Invalid IP address: " << ip << std::endl;
            close(outSock);
            return;
        }

        if(connect(outSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
            if(errno != EINPROGRESS) {
                perror("Connect failed");
                close(outSock);
                return;
            }
        }

        struct pollfd pfd;
        pfd.fd = outSock;
        pfd.events = POLLIN;
        pollfds.push_back(pfd);

        // Add to clients map
        clients[outSock] = new Client(outSock, ip, port);

        std::cout << "Connected to remote server at " << ip << ":" << port 
                  << " (sock fd: " << outSock << ")" << std::endl;

        std::string heloMsg = "HELO," + myGroupID;
        sendFormattedMessage(outSock, heloMsg);
    } else if(tokens[0] == "Group14isthebest") {
        client_sock = clientSocket;
    } else if(tokens[0] == "SENDMSG" && clientSocket == client_sock) {
        if(tokens.size() < 3) return;

        std::string groupID = tokens[1];
        std::string msg;
        for(auto i = tokens.begin()+2; i != tokens.end(); i++)
            msg += *i + " ";

        for (auto const& pair : clients) {
            if (pair.second->name == groupID) {
                send(pair.second->sock, msg.c_str(), msg.length(), 0);
                break;
            }
        }

    } else if(tokens[0] == "GETMSG") {
        // TODO
    } else if (tokens[0].rfind("KEEPALIVE,", 0) == 0) {
        // Received a KEEPALIVE with a count, e.g. KEEPALIVE,5
        // Update our receive timestamp, parse and log the reported count.
        lastKeepaliveReceivedAt[clientSocket] = time(nullptr);

        // Extract the number after the comma
        unsigned int reported = 0;
        try {
            // tokens[0] is like "KEEPALIVE,123"; find comma and parse the rest
            size_t comma = tokens[0].find(',');
            if (comma != std::string::npos && comma + 1 < tokens[0].size()) {
                reported = static_cast<unsigned int>(std::stoul(tokens[0].substr(comma + 1)));
            }
        } catch(...) {
            // Ignore malformed counts silently
        }
        std::cout << "KEEPALIVE received from fd " << clientSocket
                  << ": pending-for-us=" << reported << std::endl;
    } else if (tokens[0].find("HELO,") == 0) {
        // Expected format: HELO,<FROM_GROUP_ID>,<PORT>
        std::vector<std::string> parts;
        std::stringstream ss(tokens[0]);
        std::string item;
        while (std::getline(ss, item, ',')) {
            parts.push_back(item);
        }

        int reportedPort = -1;

        std::string groupID = parts[1];

        if (parts.size() == 3) {
            reportedPort = std::stoi(parts[2]);
        }

        if (clients.find(clientSocket) != clients.end()) {
            Client* sender = clients[clientSocket];
            sender->name = groupID;

            if (reportedPort != -1) {
                sender->port = reportedPort;
            }

            std::cout << "Recognized HELO from: " << groupID 
                    << " (port: " << reportedPort << ")" << std::endl;

            // Prepare SERVERS response
            std::string myIP = getLocalIPAddress();
            int myListenPort = port;

            std::ostringstream response;
            response << "SERVERS," << myGroupID << "," << myIP << "," << myListenPort << ";";

            for (const auto& pair : clients) {
                if (pair.first == clientSocket) continue;

                Client* c = pair.second;
                if (!c->name.empty() && !c->ip.empty()) {
                    response << c->name << "," << c->ip << "," << c->port << ";";
                }
            }

            std::string payload = response.str();

            sendFormattedMessage(clientSocket, payload);
            std::cout << "Sent SERVERS to " << groupID << ": " << payload << std::endl;
        }
    } else {
        std::cout << "Unknown command from client: " << buffer << std::endl;
    }
}


int main(int argc, char* argv[]) {
    if(argc != 2) {
        std::cerr << "Usage: server <port>" << std::endl;
        return 1;
    }

    int port = atoi(argv[1]);
    int listenSock = open_socket(port);
    if(listenSock < 0) return 1;

    if(listen(listenSock, BACKLOG) < 0) {
        perror("Listen failed");
        return 1;
    }

    std::cout << "Listening on port: " << port << std::endl;

    std::vector<struct pollfd> pollfds;
    struct pollfd listenPoll;
    listenPoll.fd = listenSock;
    listenPoll.events = POLLIN;
    pollfds.push_back(listenPoll);

    bool running = true;
    char buffer[1025];

    while(running) {
        // Use a finite poll timeout so we wake up periodically to send KEEPALIVEs.
        // 1000 ms = 1s wake-up cadence (well under the 60s send limit per peer).
        int pollCount = poll(pollfds.data(), pollfds.size(), 1000);
        if(pollCount < 0) {
            perror("poll failed");
            break;
        }

        for(size_t i = 0; i < pollfds.size(); i++) {
            if(pollfds[i].revents & POLLIN) { 
                if(pollfds[i].fd == listenSock) {
                    // New connection
                    struct sockaddr_in client;
                    socklen_t clientLen = sizeof(client);
                    int clientSock = accept(listenSock, (struct sockaddr *)&client, &clientLen);
                    if(clientSock >= 0) {
                        setNonBlocking(clientSock);

                        struct pollfd pfd;
                        pfd.fd = clientSock;
                        pfd.events = POLLIN;
                        pollfds.push_back(pfd);

                        char clientIP[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &client.sin_addr, clientIP, INET_ADDRSTRLEN);
                        int clientPort = ntohs(client.sin_port);
                        char ipStr[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(client.sin_addr), ipStr, INET_ADDRSTRLEN);
                        
                        clients[clientSock] = new Client(clientSock, std::string(ipStr), clientPort);

                        std::cout << "Client connected: " << clientSock 
                                << " (port " << clientPort << ")" << std::endl;

                        std::string heloMsg = "HELO," + myGroupID;
                        sendFormattedMessage(clientSock, heloMsg);
                        std::cout << "Sent HELO to " << ipStr << ":" << clientPort << std::endl;
                    }
                } else {
                    memset(buffer, 0, sizeof(buffer));
                    int r = recv(pollfds[i].fd, buffer, sizeof(buffer), 0);
                    if(r <= 0) {
                        closeClient(pollfds[i].fd, pollfds);
                        i--; 
                    } else {
                        // Parse the formatted message
                        std::string payload;
                        if (parseMessage(buffer, r, payload)) {
                            std::cout << "Received command: " << payload << std::endl;
                            // Convert payload to char* for clientCommand
                            char cmd_buffer[1025];
                            strncpy(cmd_buffer, payload.c_str(), sizeof(cmd_buffer) - 1);
                            cmd_buffer[sizeof(cmd_buffer) - 1] = '\0';
                            
                            clientCommand(pollfds[i].fd, cmd_buffer, pollfds, port);
                        } else {
                            std::cerr << "Failed to parse message from client " 
                                      << pollfds[i].fd << std::endl;
                        }
                    }
                }
            }
        }

        // After handling any IO events (or timeout), iterate peers and send KEEPALIVEs
        // if at least a minute has passed since the last send to that peer.
        for (const auto &kv : clients) {
            int peerSock = kv.first;
            maybeSendKeepalive(peerSock);
        }
    }

    close(listenSock);
    return 0;
}
