CXX := g++
CXXFLAGS := -std=c++11 -Wall -Wextra

all: client server

client: client.cpp
	$(CXX) $(CXXFLAGS) client.cpp -o client

server: server.cpp
	$(CXX) $(CXXFLAGS) server.cpp -o server

clean:
	rm -f client server *.o

.PHONY: all clean
