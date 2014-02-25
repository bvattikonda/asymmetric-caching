CFLAGS = -g
CLIBS = -lrt -lnfnetlink -lnetfilter_queue

all: pc_client 

OBJECTS = pc_client.o 
UTIL_OBJECTS = ../common/util.o ../common/rabin.o ../common/lookup3.o\
               ../common/pc_common.o

pc_client : $(OBJECTS) $(UTIL_OBJECTS)
	g++ $(CFLAGS) -o $@ $(OBJECTS) $(UTIL_OBJECTS) $(CLIBS)

%.o : %.cpp
	g++ $(CFLAGS) -c $< -I../include

clean :
	rm -f *.o pc_client
