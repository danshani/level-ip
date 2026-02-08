/*
 * FEC test sender — connects to a server and sends a large payload
 * through the level-ip FEC-enabled TCP stack.
 * Build: cc -o apps/fec_sender apps/fec_sender.c
 * Run:   ./tools/level-ip ./apps/fec_sender <host> <port>
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

#define DEFAULT_PAYLOAD_SIZE 8192

int get_address(char *host, char *port, struct sockaddr *addr)
{
    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int s = getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(s));
        return 1;
    }
    for (rp = result; rp; rp = rp->ai_next) {
        *addr = *rp->ai_addr;
        freeaddrinfo(result);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: %s <host> <port> [size_bytes]\n", argv[0]);
        return 1;
    }

    int payload_size = DEFAULT_PAYLOAD_SIZE;
    if (argc >= 4) {
        payload_size = atoi(argv[3]);
        if (payload_size <= 0 || payload_size > 10*1024*1024) {
            printf("Invalid size (max 10MB)\n");
            return 1;
        }
    }

    struct sockaddr addr;
    if (get_address(argv[1], argv[2], &addr) != 0) {
        printf("Could not resolve host\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    if (connect(sock, &addr, sizeof(addr)) == -1) {
        perror("connect");
        return 1;
    }

    printf("Connected, sending %d bytes...\n", payload_size);

    /* Build a recognizable payload pattern */
    char *buf = malloc(payload_size);
    if (!buf) { perror("malloc"); return 1; }
    for (int i = 0; i < payload_size; i++) {
        buf[i] = 'A' + (i % 26);
    }

    /* Write in small chunks (~1 FEC block = 5*MSS ≈ 7500 bytes)
     * so the socket write-lock is released between chunks, allowing
     * the RX thread to process feedback packets for adaptive FEC. */
    int chunk = 7500;
    int sent = 0;
    while (sent < payload_size) {
        int to_send = payload_size - sent;
        if (to_send > chunk) to_send = chunk;
        int n = write(sock, buf + sent, to_send);
        if (n <= 0) {
            perror("write");
            break;
        }
        sent += n;
        printf("Sent %d / %d bytes\n", sent, payload_size);
        if (sent < payload_size)
            usleep(15000);  /* 15ms between chunks for feedback processing */
    }

    printf("Done sending. Waiting for ACK...\n");
    /* Read a small ack from the server */
    char ack[64] = {0};
    read(sock, ack, sizeof(ack));
    printf("Server response: %s\n", ack);

    free(buf);
    close(sock);
    return 0;
}
