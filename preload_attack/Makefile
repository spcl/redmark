APPS = victim attacker

LDFLAGS =  -libverbs -lpthread #-ldl
CFLAGS += -Wall -std=c++11 -I./  

all: CFLAGS += -O2
all: ${APPS}
 
clean:
	$(foreach fname,${APPS}, rm -f ${fname})

victim: clean
	g++ victim.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm -L./ -o victim

attacker: clean
	g++ attacker.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o attacker


debug: CFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: all clean
