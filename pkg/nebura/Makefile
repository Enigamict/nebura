CC = gcc
SRCS = ipv4add.c libnetlink.c
CFLAGS = -Wall -Wextra
OBJS = $(SRCS:%.c=%.o)

all :
	$(CC) $(CFLAGS) -I ./ -c ipv4add.c libnetlink.c 
	ar rcs libipv4add.a $(OBJS)

.PHONY: clean
clean:
	rm $(OBJS) libipv4add.a