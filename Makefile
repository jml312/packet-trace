CFLAGS=-g -Wall -Werror

TARGETS=proj4.c hashtable.c

EXECUTABLE=proj4

all: $(TARGETS)
	cc $(CFLAGS) -o $(EXECUTABLE) $(TARGETS)
	
clean:
	rm -f $(EXECUTABLE)
	rm -rf $(EXECUTABLE).dSYM
