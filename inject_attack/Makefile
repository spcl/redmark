APPS = spoofv1 spoofv2 server client

LDFLAGS =  -libverbs -lpthread #-ldl
CFLAGS += -Wall -std=c++11 -I./  

all: CFLAGS += -O2
all: ${APPS}

spoofv2: clean
	g++ spoofv2.cpp --std=c++11 -lz -o spoofv2
spoofv1: clean
	g++ spoofv1.cpp --std=c++11 -lz -o spoofv1
clean:
	$(foreach fname,${APPS}, rm -f ${fname})

server: clean
	g++ server.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o server

client: clean
	g++ client.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client


debug: CFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: all clean
