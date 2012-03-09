CFLAGS = -g
CLIBS = -lrt -lnfnetlink -lnetfilter_queue 

all: as_base_station 

OBJECTS = as_base_station.o
UTIL_OBJECTS = ../common/util.o ../common/rabin.o ../common/lookup3.o\
               ../common/as_common.o

as_base_station : $(OBJECTS) $(UTIL_OBJECTS)
	g++ $(CFLAGS) -o $@ $(OBJECTS) $(UTIL_OBJECTS) $(CLIBS)

%.o : %.cpp
	g++ $(CFLAGS) -c $< -I../include

clean :
	rm -f *.o as_base_station
