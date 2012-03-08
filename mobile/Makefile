CFLAGS = -g 
CLIBS = -lrt -lnfnetlink -lnetfilter_queue

all: as_mobile 

OBJECTS = as_mobile.o detect_boundary.o best_matched_flowlet.o
UTIL_OBJECTS = ../common/util.o ../common/rabin.o ../common/lookup3.o\
               ../common/as_common.o

as_mobile : $(OBJECTS) $(UTIL_OBJECTS)
	g++ $(CFLAGS) -o $@ $(OBJECTS) $(UTIL_OBJECTS) $(CLIBS)

%.o : %.cpp
	g++ $(CFLAGS) -c $< $(CLIBS) -I../include

clean :
	rm -f *.o as_mobile
