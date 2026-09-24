# Makefile for reactor-server

CC = gcc
CFLAGS = -Wall -Wextra -g


all = epoll_echo_server

VPATH = src:include

epoll_echo_server: epoll_echo.c
	$(CC) $(CFLAGS) -o epoll_echo.c

.PHONY: clean
clean:
	rm -rf *.o epoll_echo_server
