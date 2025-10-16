//
// Simple chat client for TSAM-409
//
// Command line: ./chat_client 4000 
//
// Author: Jacky Mallett (jacky@ru.is)
//
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <vector>
#include <thread>

#include <iostream>
#include <sstream>
#include <thread>
#include <map>

// Debug function to print message in hex format
void printHex(const char* data, int length) {
    printf("Formatted message (%d bytes): ", length);
    for(int i = 0; i < length; i++) {
        printf("%02X ", (unsigned char)data[i]);
    }
    printf("\n");
    
    // Also print breakdown
    printf("  SOH: %02X\n", (unsigned char)data[0]);
    uint16_t len;
    memcpy(&len, &data[1], 2);
    printf("  Length (network): %04X (host: %d)\n", len, ntohs(len));
    printf("  STX: %02X\n", (unsigned char)data[3]);
    printf("  Command: ");
    for(int i = 4; i < length - 1; i++) {
        printf("%c", data[i]);
    }
    printf("\n  ETX: %02X\n", (unsigned char)data[length-1]);
}

// Helper function to send formatted message
void sendFormattedMessage(int sock, const std::string& command) {
    uint16_t total_length = 5 + command.length();
    uint16_t network_length = htons(total_length);
    
    char formatted_message[1024];
    int pos = 0;
    
    formatted_message[pos++] = 0x01; // SOH
    memcpy(&formatted_message[pos], &network_length, 2);
    pos += 2;
    formatted_message[pos++] = 0x02; // STX
    memcpy(&formatted_message[pos], command.c_str(), command.length());
    pos += command.length();
    formatted_message[pos++] = 0x03; // ETX
    
    send(sock, formatted_message, pos, 0);
}

// Helper functions for leaderboard commands
void sendGetMsgs(int sock, const std::string& groupId) {
    std::string command = "GETMSGS," + groupId;
    sendFormattedMessage(sock, command);
    std::cout << "Sent GETMSGS for group: " << groupId << std::endl;
}

void sendSendMsg(int sock, const std::string& toGroup, const std::string& message) {
    std::string command = "SENDMSG " + toGroup + " " + message;
    sendFormattedMessage(sock, command);
    std::cout << "Sent SENDMSG to " << toGroup << ": " << message << std::endl;
}

void sendStatusReq(int sock) {
    std::string command = "STATUSREQ";
    sendFormattedMessage(sock, command);
    std::cout << "Sent STATUSREQ" << std::endl;
}

// Threaded function for handling responss from server

void listenServer(int serverSocket)
{
    int nread;                                  // Bytes read from socket
    char buffer[1025];                          // Buffer for reading input

    while(true)
    {
       memset(buffer, 0, sizeof(buffer));
       nread = read(serverSocket, buffer, sizeof(buffer));

       if(nread == 0)                      // Server has dropped us
       {
          printf("Over and Out\n");
          exit(0);
       }
       else if(nread > 0)
       {
          printf("%s\n", buffer);
       }
    }
}

int main(int argc, char* argv[])
{
   struct addrinfo hints, *svr;              // Network host entry for server
   struct sockaddr_in serv_addr;           // Socket address for server
   int serverSocket;                         // Socket used for server 
   int nwrite;                               // No. bytes written to server
   char buffer[1025];                        // buffer for writing to server
   bool finished;                   
   int set = 1;                              // Toggle for setsockopt

   if(argc != 3)
   {
        printf("Usage: client <ip  port>\n");
        printf("Ctrl-C to terminate\n");
        exit(0);
   }

   hints.ai_family   = AF_INET;            // IPv4 only addresses
   hints.ai_socktype = SOCK_STREAM;

   memset(&hints,   0, sizeof(hints));

   if(getaddrinfo(argv[1], argv[2], &hints, &svr) != 0)
   {
       perror("getaddrinfo failed: ");
       exit(0);
   }

   struct hostent *server;
   server = gethostbyname(argv[1]);

   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr,
      (char *)&serv_addr.sin_addr.s_addr,
      server->h_length);
   serv_addr.sin_port = htons(atoi(argv[2]));

   serverSocket = socket(AF_INET, SOCK_STREAM, 0);

   // Turn on SO_REUSEADDR to allow socket to be quickly reused after 
   // program exit.

   if(setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
   {
       printf("Failed to set SO_REUSEADDR for port %s\n", argv[2]);
       perror("setsockopt failed: ");
   }

   
   if(connect(serverSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr) )< 0)
   {
       // EINPROGRESS means that the connection is still being setup. Typically this
       // only occurs with non-blocking sockets. (The serverSocket above is explicitly
       // not in non-blocking mode, so this check here is just an example of how to
       // handle this properly.)
       if(errno != EINPROGRESS)
       {
         printf("Failed to open socket to server: %s\n", argv[1]);
         perror("Connect failed: ");
         exit(0);
       }
   }

    // Listen and print replies from server
   std::thread serverThread(listenServer, serverSocket);

   finished = false;
   
   // Send initial admin authentication
   sendFormattedMessage(serverSocket, "Group14isthebest");
   
   // Send some initial commands to boost leaderboard
   std::cout << "Sending initial commands to boost leaderboard..." << std::endl;
   sendStatusReq(serverSocket);
   sendSendMsg(serverSocket, "A5_69", "Hello from A5_14!");
   sendSendMsg(serverSocket, "Instr_1", "Test message");
   sendSendMsg(serverSocket, "ORACLE", "Another test");
   sendGetMsgs(serverSocket, "A5_69");
   sendGetMsgs(serverSocket, "Instr_1");
   sendGetMsgs(serverSocket, "ORACLE");
   
   while(!finished)
   {
       bzero(buffer, sizeof(buffer));

       fgets(buffer, sizeof(buffer), stdin);

       //format the message to this format <SOH><length><STX><command><ETX>
       std::string command(buffer);
       command = command.substr(0, command.find('\n')); // remove the newline
       
       // Handle special commands
       if (command == "getmsgs") {
           std::cout << "Enter group ID: ";
           std::string groupId;
           std::getline(std::cin, groupId);
           sendGetMsgs(serverSocket, groupId);
           continue;
       } else if (command == "sendmsg") {
           std::cout << "Enter target group: ";
           std::string toGroup;
           std::getline(std::cin, toGroup);
           std::cout << "Enter message: ";
           std::string message;
           std::getline(std::cin, message);
           sendSendMsg(serverSocket, toGroup, message);
           continue;
       } else if (command == "statusreq") {
           sendStatusReq(serverSocket);
           continue;
       } else if (command == "boost") {
           // Send multiple commands to boost leaderboard
           std::cout << "Boosting leaderboard metrics..." << std::endl;
           for (int i = 0; i < 5; i++) {
               sendStatusReq(serverSocket);
               sendSendMsg(serverSocket, "A5_69", "Boost message " + std::to_string(i));
               sendGetMsgs(serverSocket, "A5_69");
               usleep(100000); // 100ms delay
           }
           continue;
       }

       // Send the command as-is
       sendFormattedMessage(serverSocket, command);

   }
}
