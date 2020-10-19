APPS = main

LDFLAGS =  -libverbs 
CFLAGS += -Wall -std=c++11 -I./  

all: CFLAGS += -O2
all: ${APPS}

main: clean
	g++ main.cpp   $(CFLAGS) $(LDFLAGS) -o main
clean:
	$(foreach fname,${APPS}, rm -f ${fname})

debug: CFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: all clean
