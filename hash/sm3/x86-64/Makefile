# Flag
CC = gcc
CFLAGS = -O3 -mavx2
# LFLAGS = -O3

# Files
SRCS = sm3.c main.c

# Deafult option: release
# For debug option, USAGE: make /f Makefile2 DEBUG=1
ifeq ($(DEBUG), 1)
	# Debug mode, Rewrite the CFLAG and LFLAGS
	CFLAGS = -Wall -DDEBUG -g 
	LFLAGS = 
endif

ifeq ($(NOOPT), 1)
	CFLAGS = -mavx2
	LFLAGS = 
endif

CFLAGS += -I../..

# Targets
sm3 : $(SRCS)
	$(CC) $(CFLAGS) -o sm3 $(SRCS) $(LFLAGS)

clean:
	rm -f sm3

	
