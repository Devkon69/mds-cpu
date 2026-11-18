/* SPDX-License-Identifier: GPL-3.0-or-later */
/* platform.h - sockets, time, sleep for Windows (Winsock2) and Linux */
#ifndef PLATFORM_H
#define PLATFORM_H
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET sock_t;
#define SOCK_INVALID INVALID_SOCKET
#define sock_close(s) closesocket(s)
#define sock_errno() WSAGetLastError()
#define SOCK_EWOULDBLOCK WSAEWOULDBLOCK
#define SOCK_EINPROGRESS WSAEWOULDBLOCK
#define SOCK_EINTR WSAEINTR
#define sock_poll(p, n, ms) WSAPoll(p, n, ms)
typedef WSAPOLLFD sock_pollfd;
#define MSG_NOSIGNAL 0
static int sock_set_nonblock(sock_t s, int nb) { u_long m = nb ? 1 : 0; return ioctlsocket(s, FIONBIO, &m); }
static void sock_init(void) { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); }
static void sleep_ms(int ms) { Sleep(ms); }
static double now_s(void)
{
    static LARGE_INTEGER f; LARGE_INTEGER c;
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
}
static const char *sock_strerror(int e)
{
    static char b[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, e, 0, b, sizeof b, NULL);
    for (char *q = b; *q; q++) if (*q == '\r' || *q == '\n') *q = ' ';
    return b;
}
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
typedef int sock_t;
#define SOCK_INVALID (-1)
#define sock_close(s) close(s)
#define sock_errno() errno
#define SOCK_EWOULDBLOCK EAGAIN
#define SOCK_EINPROGRESS EINPROGRESS
#define SOCK_EINTR EINTR
#define sock_poll(p, n, ms) poll(p, n, ms)
typedef struct pollfd sock_pollfd;
static int sock_set_nonblock(sock_t s, int nb)
{
    int f = fcntl(s, F_GETFL);
    return fcntl(s, F_SETFL, nb ? (f | O_NONBLOCK) : (f & ~O_NONBLOCK));
}
static void sock_init(void) {}
static void sleep_ms(int ms) { struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L }; nanosleep(&ts, NULL); }
static double now_s(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
static const char *sock_strerror(int e) { return strerror(e); }
#endif

#endif
