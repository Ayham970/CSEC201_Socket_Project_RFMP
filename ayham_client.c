#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/*
This function sends one RFMP packet.

Every packet contains:
1. A 4-byte number containing the message length
2. The actual message
*/
int send_packet(int socket_fd, char message[]) {
    int message_length = strlen(message);

    /*
    htonl changes the number into network byte order.
    uint32_t is an unsigned integer that always uses 4 bytes.
    */
    uint32_t network_length = htonl(message_length);

    int total_sent = 0;
    int sent;

    char *length_bytes = (char *)&network_length;

    /* Send all 4 bytes of the length */
    while (total_sent < 4) {
        sent = send(
            socket_fd,
            length_bytes + total_sent,
            4 - total_sent,
            0
        );

        if (sent <= 0) {
            return 0;
        }

        total_sent = total_sent + sent;
    }

    /* Send the complete message */
    total_sent = 0;

    while (total_sent < message_length) {
        sent = send(
            socket_fd,
            message + total_sent,
            message_length - total_sent,
            0
        );

        if (sent <= 0) {
            return 0;
        }

        total_sent = total_sent + sent;
    }

    return 1;
}


/*
This function receives one RFMP packet.

It first receives the 4-byte length and then receives
the complete message.
*/
int receive_packet(
    int socket_fd,
    char response[],
    int response_size
) {
    uint32_t network_length;
    char *length_bytes = (char *)&network_length;

    int total_received = 0;
    int received;

    /* Receive all 4 bytes of the length */
    while (total_received < 4) {
        received = recv(
            socket_fd,
            length_bytes + total_received,
            4 - total_received,
            0
        );

        if (received <= 0) {
            return 0;
        }

        total_received = total_received + received;
    }

    /* Convert the network number back to a normal number */
    int message_length = ntohl(network_length);

    /*
    Leave one empty cell for the string terminator.
    This prevents the response array from overflowing.
    */
    if (message_length <= 0 || message_length >= response_size) {
        return 0;
    }

    total_received = 0;

    /* Receive the complete message */
    while (total_received < message_length) {
        received = recv(
            socket_fd,
            response + total_received,
            message_length - total_received,
            0
        );

        if (received <= 0) {
            return 0;
        }

        total_received = total_received + received;
    }

    /* Add the string terminator */
    response[message_length] = '\0';

    return 1;
}


int main() {
    int socket_fd;
    int port = 5050;

    char server_ip[16];
    char response[1000];

    printf("Enter the server address: ");
    scanf("%15s", server_ip);

    /* Create an IPv4 TCP socket */
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_fd < 0) {
        printf("Could not create the socket.\n");
        return 1;
    }

    /*
    sockaddr_in stores the server's IPv4 address and port.
    This structure is supplied by the socket library.
    */
    struct sockaddr_in server_address = {0};

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);

    /*
    Convert an address such as 127.0.0.1 into the form
    required by the socket library.
    */
    if (
        inet_pton(
            AF_INET,
            server_ip,
            &server_address.sin_addr
        ) != 1
    ) {
        printf("Invalid server address.\n");
        close(socket_fd);
        return 1;
    }

    printf("Connecting to the server...\n");

    if (
        connect(
            socket_fd,
            (struct sockaddr *)&server_address,
            sizeof(server_address)
        ) < 0
    ) {
        printf("Could not connect to the server.\n");
        close(socket_fd);
        return 1;
    }

    printf("Connected to the server.\n");

    /* Send the unencrypted setup packet */
    if (!send_packet(socket_fd, "(SS,RFMP,v1.0,0)")) {
        printf("Could not send the setup packet.\n");
        close(socket_fd);
        return 1;
    }

    printf("Sent: (SS,RFMP,v1.0,0)\n");

    /* Receive the server's connection confirmation */
    if (!receive_packet(socket_fd, response, 1000)) {
        printf("Could not receive the server response.\n");
        close(socket_fd);
        return 1;
    }

    printf("Received: %s\n", response);

    if (strcmp(response, "(CC)") != 0) {
        printf("The server did not accept the connection.\n");
        close(socket_fd);
        return 1;
    }

    printf("Handshake completed successfully.\n");

    /* Ask the server to close the connection */
    if (!send_packet(socket_fd, "(End)")) {
        printf("Could not send the End packet.\n");
        close(socket_fd);
        return 1;
    }

    printf("Sent: (End)\n");

    /* Receive the closing acknowledgement */
    if (!receive_packet(socket_fd, response, 1000)) {
        printf("Could not receive the closing response.\n");
        close(socket_fd);
        return 1;
    }

    printf("Received: %s\n", response);

    close(socket_fd);

    printf("Connection closed.\n");

    return 0;
}
