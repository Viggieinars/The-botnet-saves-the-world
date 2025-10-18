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
#include <iomanip>

#define BACKLOG 5


std::string getTimestamp() {
    time_t now = time(nullptr);
    struct tm* timeinfo = localtime(&now);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return std::string(buffer);
}

// Logging macros with timestamps
#define LOG(msg) std::cout << "[" << getTimestamp() << "] " << msg << std::endl
#define LOG_ERROR(msg) std::cerr << "[" << getTimestamp() << "] ERROR: " << msg << std::endl

int client_sock = -1;
std::string myGroupID = "A5_14"; // Our group ID

// Client/server connection info
class Client {
public:
    int sock; // The socket number
    std::string name; // The group ID - Empty until HELO
    std::string ip; // The IP address of the server
    int port; // The port of the server

    Client(int socket, std::string ipAddr, int portNumber) : sock(socket), ip(ipAddr), port(portNumber) {} // Constructor
    ~Client() {} // Destructor
};

std::map<int, Client*> clients; // Client map - Socket number to Client object

// Forward declarations
void sendFormattedMessage(int sock, const std::string& msg);

static std::map<int, time_t> lastKeepaliveSentAt; // To only send keepalive once per minute
static std::map<int, time_t> lastKeepaliveHeardAt; // To Detect dead connections
static std::map<std::string, time_t> lastAutoConnectAttemptAt; // To Prevent spam
static std::map<std::string, std::list<std::string>> pendingMessagesByGroup; // To Store messages for later delivery
static std::map<int, std::string> recvBuffers; // To Store partial messages


void setNonBlocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}


void sendFormattedMessage(int sock, const std::string& msg) {

    const char SOH = 0x01;  // Start of Header
    const char STX = 0x02;  // Start of Text
    const char ETX = 0x03;  // End of Text
    
    uint16_t total_length = static_cast<uint16_t>(msg.length() + 5);
    
    std::string sendbuf;
    sendbuf.resize(total_length);
    sendbuf[0] = SOH; // Add SOH
    uint16_t network_length = htons(total_length);
    memcpy(&sendbuf[1], &network_length, 2);
    sendbuf[3] = STX; // Add STX
    memcpy(&sendbuf[4], msg.data(), msg.length());
    sendbuf[4 + msg.length()] = ETX; // Add ETX
    send(sock, sendbuf.data(), sendbuf.size(), 0);
}

// Count how many messages are queued for a specific peer
static unsigned int countQueuedMessages(const Client* peer) {
    if (peer == nullptr) return 0;
    if (peer->name.empty()) return 0;
    
    auto it = pendingMessagesByGroup.find(peer->name);
    if (it == pendingMessagesByGroup.end()) return 0;
    
    return static_cast<unsigned int>(it->second.size());
}


// Route message to recipient (immediate delivery if connected, otherwise queue for later)
static void routeMessage(const std::string &toGroup, const std::string &fromGroup, const std::string &text) {
    
    const size_t MAX_CMD_LEN = 5000;
    const size_t estimatedLen = strlen("SENDMSG,,,") + toGroup.size() + fromGroup.size() + text.size();
    
    if (estimatedLen > MAX_CMD_LEN) {
        LOG_ERROR("SENDMSG too large (" << estimatedLen << " bytes) - dropping message");
        return;
    }
    
    // Check if destination group is currently connected
    for (const auto &kv : clients) {
        const Client* c = kv.second;
        if (!c) continue;
        
        if (c->name == toGroup) {
            std::ostringstream payload;
            payload << "SENDMSG," << toGroup << "," << fromGroup << "," << text;
            sendFormattedMessage(kv.first, payload.str());
            LOG("SENT: Message to " << toGroup << " from " << fromGroup << " via " << c->name);
            return;
        }
    }
    
    // Store message for later retrieval
    std::ostringstream stored;
    stored << fromGroup << "," << text;
    pendingMessagesByGroup[toGroup].push_back(stored.str());
    LOG("QUEUED: Message for " << toGroup << " from " << fromGroup << " (not connected)");
}


static void sendKeepaliveIfDue(int peerSock) {
    time_t now = time(nullptr);

    // Check if we already sent KEEPALIVE in the last 60 seconds
    auto it = lastKeepaliveSentAt.find(peerSock);
    if (it != lastKeepaliveSentAt.end()) {
        if (difftime(now, it->second) < 60.0) return;
    }

    auto cIt = clients.find(peerSock);
    if (cIt == clients.end() || cIt->second == nullptr) return;

    const Client* peer = cIt->second;
    if (peer->name.empty()) return;
    if (peerSock == client_sock) return;

    unsigned int messageCount = countQueuedMessages(peer);
    std::ostringstream payload;
    payload << "KEEPALIVE," << messageCount;
    sendFormattedMessage(peerSock, payload.str());
    LOG("SENT: KEEPALIVE," << messageCount << " to " << peer->name);

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


// Close connection and clean up all associated data structures
void closeConnection(int clientSocket, std::vector<struct pollfd> &pollfds) {
    LOG("Connection closed: socket " << clientSocket);
    
    close(clientSocket);
    
    auto it = clients.find(clientSocket);
    if (it != clients.end()) {
        delete it->second;
        clients.erase(it);
    }
    
    lastKeepaliveSentAt.erase(clientSocket);
    lastKeepaliveHeardAt.erase(clientSocket);
    recvBuffers.erase(clientSocket);
    
    pollfds.erase(std::remove_if(pollfds.begin(), pollfds.end(),
        [clientSocket](struct pollfd &p) { return p.fd == clientSocket; }),
        pollfds.end());
}


// Command dispatcher - routes all incoming commands to appropriate handlers
void clientCommand(int clientSocket, char *buffer, std::vector<struct pollfd> &pollfds, int port) {
    std::vector<std::string> tokens;
    std::stringstream stream(buffer);
    std::string token;

    (void)port; // suppress unused parameter warning; keep signature for future use

    while(stream >> token) tokens.push_back(token);

    if(tokens.empty()) return;

    //=============================================================================
    // ADMIN COMMANDS (from our authenticated client)
    //=============================================================================

    // CONNECT - establish outgoing connection to another server
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

        LOG("CONNECT: Outgoing connection to " << ip << ":" << port << " (socket " << outSock << ")");

        std::string heloMsg = "HELO," + myGroupID;
        sendFormattedMessage(outSock, heloMsg);
        LOG("SENT: HELO," << myGroupID << " to " << ip << ":" << port);
    
    // LISTSERVERS - reply with list of connected servers
    } else if (tokens[0] == "LISTSERVERS" && clientSocket == client_sock) {
        std::ostringstream resp;
        resp << "SERVERS,";
        resp << myGroupID << "," << getLocalIPAddress() << "," << port << ";";
        for (const auto &kv : clients) {
            const Client* c = kv.second;
            if (!c) continue;
            if (kv.first == client_sock) continue; // skip admin
            if (c->name.empty()) continue; // only identified peers
            if (c->name == myGroupID) continue; // avoid listing ourselves again
            resp << c->name << "," << c->ip << "," << c->port << ";";
        }
        sendFormattedMessage(clientSocket, resp.str());
        LOG("SENT: " << resp.str());
    
    // CLIENTAUTH - authenticate admin client
    } else if(tokens[0] == "CLIENTAUTH") {
        client_sock = clientSocket;
    
    // SENDMSG - send message from admin client to target group
    } else if(tokens[0] == "SENDMSG" && clientSocket == client_sock) {
        if(tokens.size() < 3) return;

        std::string toGroupID = tokens[1];
        std::string msg;
        for(auto i = tokens.begin()+2; i != tokens.end(); i++) {
            if(i != tokens.begin()+2) msg += " ";
            msg += *i;
        }

        // Route the message (immediate delivery or queue for later)
        routeMessage(toGroupID, myGroupID, msg);
    
    // GETMSG - retrieve one queued message for our group
    } else if(tokens[0] == "GETMSG" && clientSocket == client_sock) {
        auto itp = pendingMessagesByGroup.find(myGroupID);
        if (itp == pendingMessagesByGroup.end() || itp->second.empty()) {
            sendFormattedMessage(clientSocket, "NO_MSG");
        } else {
            sendFormattedMessage(clientSocket, "SENDMSG," + myGroupID + "," + itp->second.front());
            LOG("SENT: Queued message for " << myGroupID << " to admin client");
            itp->second.pop_front();
        }

    //=============================================================================
    // PEER-TO-PEER MESSAGE ROUTING
    //=============================================================================

    } else if (tokens[0].rfind("SENDMSG,", 0) == 0) {
        // SENDMSG from peers - format: SENDMSG,<TO>,<FROM>,<TEXT>
        const std::string &s = tokens[0];
        size_t p1 = s.find(',');
        if (p1 == std::string::npos) return;
        size_t p2 = s.find(',', p1 + 1);
        if (p2 == std::string::npos) return;
        size_t p3 = s.find(',', p2 + 1);
        if (p3 == std::string::npos) return;
        
        std::string toGroup = s.substr(p1 + 1, p2 - (p1 + 1));
        std::string fromGroup = s.substr(p2 + 1, p3 - (p2 + 1));
        std::string text = s.substr(p3 + 1);
        
        routeMessage(toGroup, fromGroup, text);

    //=============================================================================
    // PEER-TO-PEER CONTROL COMMANDS
    //=============================================================================

    } else if (tokens[0].rfind("GETMSGS,", 0) == 0) {
        // GETMSGS - return one queued message for the specified group
        // Format: GETMSGS,<GROUP>
        std::string target = tokens[0].substr(8);
        
        auto itp = pendingMessagesByGroup.find(target);
        if (target.empty() || itp == pendingMessagesByGroup.end() || itp->second.empty()) {
            sendFormattedMessage(clientSocket, std::string("NO_MSG"));
        } else {
            std::string entry = itp->second.front();
            itp->second.pop_front();
            std::ostringstream resp;
            resp << "SENDMSG," << target << "," << entry;
            sendFormattedMessage(clientSocket, resp.str());
            LOG("SENT: Queued message for " << target << " (retrieved via GETMSGS)");
        }
    
    //=============================================================================
    // PEER-TO-PEER STATUS & MONITORING
    //=============================================================================
    
    } else if (tokens[0].rfind("KEEPALIVE,", 0) == 0) {
        // KEEPALIVE - update last-heard timestamp for this peer
        lastKeepaliveHeardAt[clientSocket] = time(nullptr);
    } else if (tokens[0] == "STATUSREQ") {
        // Build STATUSRESP,<group,count>,... for all known peers and queued groups
        std::map<std::string, unsigned int> countsByGroup;

        // Seed from queued messages
        for (const auto &kv : pendingMessagesByGroup) {
            countsByGroup[kv.first] = static_cast<unsigned int>(kv.second.size());
        }

        // Ensure all identified 1-hop peers are present (with 0 if none queued)
        for (const auto &kv : clients) {
            const Client* c = kv.second;
            if (!c) continue;
            if (kv.first == client_sock) continue; // skip admin
            if (c->name.empty()) continue; // only identified peers
            if (countsByGroup.find(c->name) == countsByGroup.end()) {
                countsByGroup[c->name] = 0;
            }
        }

        std::ostringstream resp;
        resp << "STATUSRESP";
        for (const auto &kv : countsByGroup) {
            resp << "," << kv.first << "," << kv.second;
        }

        sendFormattedMessage(clientSocket, resp.str());
        LOG("SENT: " << resp.str());

    //=============================================================================
    // PROTOCOL HANDSHAKE & DISCOVERY
    //=============================================================================

    } else if (tokens[0].find("HELO,") == 0) {
        // Expected: HELO,<FROM_GROUP_ID>[,<PORT>]; reply with SERVERS list per spec
        std::vector<std::string> parts;
        std::stringstream ss(tokens[0]);
        std::string item;
        while (std::getline(ss, item, ',')) {
            parts.push_back(item);
        }

        if (parts.size() >= 2) {
            std::string peerGroup = parts[1];
            if (clients.find(clientSocket) != clients.end()) {
                Client* sender = clients[clientSocket];
                sender->name = peerGroup;
            }

            // Deduplicate: if another socket already claims this group, close the older one (keep lowest fd)
            int existingFd = -1;
            for (const auto &kv2 : clients) {
                if (kv2.first == clientSocket) continue;
                const Client* other = kv2.second;
                if (!other) continue;
                if (other->name == peerGroup) { existingFd = kv2.first; break; }
            }
            if (existingFd != -1) {
                int keepFd = std::min(existingFd, clientSocket);
                int dropFd = (keepFd == existingFd) ? clientSocket : existingFd;
                LOG("Duplicate connection for group " << peerGroup << " detected, closing socket " << dropFd);
                closeConnection(dropFd, pollfds);
            }
        }

        // Build SERVERS response: first entry must be our own (group, ip, listen port)
        std::ostringstream resp;
        resp << "SERVERS,";
        resp << myGroupID << "," << getLocalIPAddress() << "," << port << ";";

        // Append directly connected 1-hop servers (exclude admin and empty names)
        for (const auto &kv : clients) {
            const Client* c = kv.second;
            if (!c) continue;
            if (kv.first == client_sock) continue; // skip admin client
            if (c->name.empty()) continue; // only identified peers
            if (c->name == myGroupID) continue; // avoid listing ourselves again
            resp << c->name << "," << c->ip << "," << c->port << ";";
        }

        std::string serversMsg = resp.str();
        sendFormattedMessage(clientSocket, serversMsg);
        LOG("SENT: " << serversMsg);
    
    // SERVERS - process peer list and auto-connect to discovered servers
    } else if (tokens[0].find("SERVERS") == 0) {
        LOG("RECEIVED: " << tokens[0]);

        // === PARSE SERVER LIST ===
        std::string serverList = tokens[0].substr(8);
        std::stringstream entryStream(serverList);
        std::string entry;
        
        while (std::getline(entryStream, entry, ';')) {
            if (entry.empty()) continue;

            // Parse entry: GROUP,IP,PORT
            std::vector<std::string> parts;
            std::stringstream partStream(entry);
            std::string part;
            while (std::getline(partStream, part, ',')) {
                parts.push_back(part);
            }

            if (parts.size() != 3) continue;
            
            std::string group = parts[0];
            std::string ip = parts[1];
            int partPort = std::stoi(parts[2]);

            // === VALIDATE ENTRY ===
            if (group.empty() || ip.empty() || partPort <= 0 || group == myGroupID) {
                continue;
            }

            LOG("Discovered server: " << group << " at " << ip << ":" << partPort);

            // === CHECK IF ALREADY CONNECTED ===
            bool alreadyConnected = false;
            for (const auto &ckv : clients) {
                const Client* c = ckv.second;
                if (!c) continue;
                if ((!c->name.empty() && c->name == group) || (c->ip == ip && c->port == partPort)) {
                    alreadyConnected = true;
                    break;
                }
            }
            if (alreadyConnected) continue;

            // === COOLDOWN GUARD (60s per ip:port) ===
            std::ostringstream key;
            key << ip << ":" << partPort;
            time_t now = time(nullptr);
            auto itLast = lastAutoConnectAttemptAt.find(key.str());
            if (itLast != lastAutoConnectAttemptAt.end() && difftime(now, itLast->second) < 60.0) {
                continue;
            }
            lastAutoConnectAttemptAt[key.str()] = now;

            // === ATTEMPT CONNECTION ===
            int outSock = socket(AF_INET, SOCK_STREAM, 0);
            if (outSock < 0) {
                perror("Failed to create outgoing socket");
                continue;
            }
            
            setNonBlocking(outSock);
            struct sockaddr_in serverAddr;
            memset(&serverAddr, 0, sizeof(serverAddr));
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(partPort);
            
            if (inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr) <= 0) {
                LOG_ERROR("Invalid IP address from SERVERS: " << ip);
                close(outSock);
                continue;
            }
            
            if (connect(outSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
                if (errno != EINPROGRESS) {
                    perror("Connect failed");
                    close(outSock);
                    continue;
                }
            }

            // === REGISTER CONNECTION & SEND HELO ===
            struct pollfd npfd;
            npfd.fd = outSock;
            npfd.events = POLLIN;
            pollfds.push_back(npfd);
            clients[outSock] = new Client(outSock, ip, partPort);
            
            LOG("Auto-connecting to discovered server " << group << " at " << ip << ":" << partPort);
            
            std::string heloMsg = "HELO," + myGroupID;
            sendFormattedMessage(outSock, heloMsg);
            LOG("SENT: HELO," << myGroupID << " to " << group);
        }
        return;

    //=============================================================================
    // UNKNOWN COMMAND
    //=============================================================================

    } else {
        LOG("RECEIVED: Unknown command: " << buffer);
    }
}


int main(int argc, char* argv[]) {
    //=============================================================================
    // INITIALIZATION
    //=============================================================================
    if(argc != 2) { std::cerr << "Usage: server <port>" << std::endl; return 1; }

    int port = atoi(argv[1]);
    int listenSock = open_socket(port);
    if(listenSock < 0) return 1;
    if(listen(listenSock, BACKLOG) < 0) { perror("Listen failed"); return 1; }

    LOG("Server " << myGroupID << " listening on port " << port);

    std::vector<struct pollfd> pollfds;
    struct pollfd listenPoll = {listenSock, POLLIN, 0};
    pollfds.push_back(listenPoll);

    char buffer[1025];

    //=============================================================================
    // MAIN EVENT LOOP
    //=============================================================================
    while(true) {
        // Poll with 1s timeout for periodic KEEPALIVE
        if(poll(pollfds.data(), pollfds.size(), 1000) < 0) { perror("poll failed"); break; }

        // === PROCESS SOCKET EVENTS ===
        for(size_t i = 0; i < pollfds.size(); i++) {
            if(!(pollfds[i].revents & POLLIN)) continue;
            
            // --- ACCEPT NEW CONNECTIONS ---
            if(pollfds[i].fd == listenSock) {
                struct sockaddr_in client;
                socklen_t clientLen = sizeof(client);
                int clientSock = accept(listenSock, (struct sockaddr *)&client, &clientLen);
                if(clientSock >= 0) {
                    setNonBlocking(clientSock);
                    struct pollfd pfd = {clientSock, POLLIN, 0};
                    pollfds.push_back(pfd);

                    char ipStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(client.sin_addr), ipStr, INET_ADDRSTRLEN);
                    int clientPort = ntohs(client.sin_port);
                    
                    clients[clientSock] = new Client(clientSock, std::string(ipStr), clientPort);
                    LOG("ACCEPT: Incoming connection from " << ipStr << ":" << clientPort << " (socket " << clientSock << ")");

                    sendFormattedMessage(clientSock, "HELO," + myGroupID);
                    LOG("SENT: HELO," << myGroupID << " to " << ipStr << ":" << clientPort);
                }
            
            // --- RECEIVE DATA FROM EXISTING CONNECTIONS ---
            } else {
                memset(buffer, 0, sizeof(buffer));
                int r = recv(pollfds[i].fd, buffer, sizeof(buffer), 0);
                
                if(r <= 0) {
                    closeConnection(pollfds[i].fd, pollfds);
                    i--; 
                } else {
                    std::string &acc = recvBuffers[pollfds[i].fd];
                    acc.append(buffer, r);

                    // --- PARSE PROTOCOL FRAMES: <SOH><len><STX><payload><ETX> ---
                    while (true) {
                        if (acc.size() < 5) break;

                        // Resync to SOH (0x01)
                        if ((unsigned char)acc[0] != 0x01) {
                            size_t pos = acc.find((char)0x01);
                            if (pos == std::string::npos) { acc.clear(); break; }
                            acc.erase(0, pos);
                            if (acc.size() < 5) break;
                        }

                        uint16_t total_length;
                        memcpy(&total_length, &acc[1], 2);
                        total_length = ntohs(total_length);

                        if (acc.size() < total_length) break;

                        // Validate STX (0x02) and ETX (0x03)
                        if ((unsigned char)acc[3] != 0x02 || (unsigned char)acc[total_length - 1] != 0x03) {
                            acc.erase(0, 1);
                            continue;
                        }

                        // Extract and dispatch payload
                        std::string payload = (total_length > 5) ? acc.substr(4, total_length - 5) : "";
                        acc.erase(0, total_length);

                        LOG("RECEIVED: " << payload);
                        char cmd_buffer[1025];
                        strncpy(cmd_buffer, payload.c_str(), sizeof(cmd_buffer) - 1);
                        cmd_buffer[sizeof(cmd_buffer) - 1] = '\0';
                        clientCommand(pollfds[i].fd, cmd_buffer, pollfds, port);
                    }
                }
            }
        }

        // === PERIODIC MAINTENANCE ===
        for (const auto &kv : clients) sendKeepaliveIfDue(kv.first);
    }

    close(listenSock);
    return 0;
}
