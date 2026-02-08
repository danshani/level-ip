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

#define PAYLOAD_SIZE 8192  /* Large enough for multiple FEC blocks */

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
    if (argc != 3) {
        printf("Usage: %s <host> <port>\n", argv[0]);
        return 1;
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

    printf("Connected, sending %d bytes...\n", PAYLOAD_SIZE);

    /* Build a recognizable payload pattern */
    char buf[PAYLOAD_SIZE];
    for (int i = 0; i < PAYLOAD_SIZE; i++) {
        buf[i] = 'A' + (i % 26);
    }

    int sent = 0;
    while (sent < PAYLOAD_SIZE) {
        int n = write(sock, buf + sent, PAYLOAD_SIZE - sent);
        if (n <= 0) {
            perror("write");
            break;
        }
        sent += n;
        printf("Sent %d / %d bytes\n", sent, PAYLOAD_SIZE);
    }

    printf("Done sending. Waiting for ACK...\n");
    /* Read a small ack from the server */
    char ack[64] = {0};
    read(sock, ack, sizeof(ack));
    printf("Server response: %s\n", ack);

    close(sock);
    return 0;
}
