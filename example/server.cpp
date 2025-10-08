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

#define BACKLOG 5

// Client info
class Client {
public:
    int sock;
    std::string name;

    Client(int socket) : sock(socket) {}
    ~Client() {}
};

std::map<int, Client*> clients;

// Helper to set non-blocking
void setNonBlocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
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

// Handle client commands
void clientCommand(int clientSocket, char *buffer) {
    std::vector<std::string> tokens;
    std::stringstream stream(buffer);
    std::string token;

    while(stream >> token) tokens.push_back(token);

    if(tokens.empty()) return;

    if(tokens[0] == "CONNECT" && tokens.size() == 2) {
        clients[clientSocket]->name = tokens[1];
    } else if(tokens[0] == "LEAVE") {
        closeClient(clientSocket, *(new std::vector<struct pollfd>()));
    } else if(tokens[0] == "WHO") {
        std::string msg;
        for(auto const& pair : clients) {
            msg += pair.second->name + ",";
        }
        if(!msg.empty()) msg.pop_back();
        send(clientSocket, msg.c_str(), msg.length(), 0);
    } else if(tokens[0] == "MSG" && tokens[1] == "ALL") {
        std::string msg;
        for(auto i = tokens.begin()+2; i != tokens.end(); i++)
            msg += *i + " ";

        for(auto const& pair : clients)
            send(pair.second->sock, msg.c_str(), msg.length(), 0);
    } else if(tokens[0] == "MSG" && tokens.size() > 2) {
        std::string recipient = tokens[1];
        std::string msg;
        for(auto i = tokens.begin()+2; i != tokens.end(); i++)
            msg += *i + " ";

        for(auto const& pair : clients) {
            if(pair.second->name == recipient) {
                send(pair.second->sock, msg.c_str(), msg.length(), 0);
            }
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
        int pollCount = poll(pollfds.data(), pollfds.size(), -1);
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

                        clients[clientSock] = new Client(clientSock);
                        std::cout << "Client connected: " << clientSock << std::endl;
                    }
                } else {
                    // Client message
                    memset(buffer, 0, sizeof(buffer));
                    int r = recv(pollfds[i].fd, buffer, sizeof(buffer), 0);
                    if(r <= 0) {
                        closeClient(pollfds[i].fd, pollfds);
                        i--; // adjust index after erase
                    } else {
                        std::cout << "Received: " << buffer << std::endl;
                        clientCommand(pollfds[i].fd, buffer);
                    }
                }
            }
        }
    }

    close(listenSock);
    return 0;
}
