CC = gcc
SRCS = netlink_code.c libnetlink.c
CFLAGS = -Wall -Wextra
OBJS = $(SRCS:%.c=%.o)

all :
	$(CC) $(CFLAGS) -I ./ -c netlink_code.c libnetlink.c 
	ar rcs libnetlink_code.a  $(OBJS)
	go generate
	cd ../../cmd/bgp/ && go build


.PHONY: clean
clean:
	rm $(OBJS) libipv4add.a 