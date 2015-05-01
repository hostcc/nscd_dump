CC = gcc
DEFINES = -D_GNU_SOURCE
CFLAGS  = -Wall -std=gnu99
LDFLAGS = 

OBJECTS = nscd_dump.o
PROGRAM = nscd_dump

all: $(PROGRAM)

nscd_dump.o: nscd-client.h nscd.h

%.o: %.c
	$(CC) -c $(DEFINES) $(INCLUDES) $(CFLAGS) $< -o $@

$(PROGRAM): $(OBJECTS)
	$(CC) $(LDFLAGS) $< -o $@

clean:
	$(RM) $(OBJECTS)
	$(RM) $(PROGRAM)
