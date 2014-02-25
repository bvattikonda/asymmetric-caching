CFLAGS = -g
CLIBS = -lrt 

OBJECTS = lookup3.o util.o rabin.o pc_common.o

all : $(OBJECTS)

%.o : %.cpp
	g++ $(CFLAGS) -c $< $(CLIBS) -I../include

clean :
	rm -f *.o
