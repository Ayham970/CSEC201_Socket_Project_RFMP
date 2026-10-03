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


/*
Base64 alphabet. Every group of 3 bytes becomes 4 of these characters.
*/
char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


/*
Encode length bytes from input into Base64 text in output.
Example: "data.txt" becomes "ZGF0YS50eHQ="
*/
void base64_encode(char *input, int length, char *output) {
    int i = 0;
    int j = 0;

    while (i < length) {
        /* Take up to 3 bytes (missing bytes count as 0) */
        unsigned char b1 = input[i];
        unsigned char b2 = 0;
        unsigned char b3 = 0;

        if (i + 1 < length) {
            b2 = input[i + 1];
        }
        if (i + 2 < length) {
            b3 = input[i + 2];
        }

        /* Split the 24 bits into four 6-bit numbers */
        output[j] = base64_chars[b1 >> 2];
        output[j + 1] = base64_chars[((b1 & 3) << 4) | (b2 >> 4)];
        output[j + 2] = base64_chars[((b2 & 15) << 2) | (b3 >> 6)];
        output[j + 3] = base64_chars[b3 & 63];

        /* Use '=' as padding when the last group was not complete */
        if (i + 1 >= length) {
            output[j + 2] = '=';
        }
        if (i + 2 >= length) {
            output[j + 3] = '=';
        }

        i = i + 3;
        j = j + 4;
    }

    output[j] = '\0';
}


/*
Return the 6-bit value of one Base64 character (0 to 63).
*/
int base64_value(char c) {
    int i;

    for (i = 0; i < 64; i++) {
        if (base64_chars[i] == c) {
            return i;
        }
    }

    /* '=' padding (or any other character) counts as 0 */
    return 0;
}


/*
Decode Base64 text from input into output.
Returns the number of decoded bytes.
*/
int base64_decode(char *input, char *output) {
    int length = strlen(input);
    int i = 0;
    int j = 0;

    while (i + 3 < length) {
        /* Four characters hold 24 bits = 3 bytes */
        int v1 = base64_value(input[i]);
        int v2 = base64_value(input[i + 1]);
        int v3 = base64_value(input[i + 2]);
        int v4 = base64_value(input[i + 3]);

        output[j] = (v1 << 2) | (v2 >> 4);
        j = j + 1;

        /* '=' means there is no second or third byte */
        if (input[i + 2] != '=') {
            output[j] = ((v2 & 15) << 4) | (v3 >> 2);
            j = j + 1;
        }
        if (input[i + 3] != '=') {
            output[j] = ((v3 & 3) << 6) | v4;
            j = j + 1;
        }

        i = i + 4;
    }

    output[j] = '\0';
    return j;
}


/*
Size of the receive buffers. A file must be smaller than this.
*/
#define BUFFER_SIZE 100000


int main() {
    int socket_fd;
    int port = 5050;

    char server_ip[16];
    char response[BUFFER_SIZE];
    char file_data[BUFFER_SIZE];
    char filename[256];
    char encoded_name[400];
    char request[500];

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
    if (!receive_packet(socket_fd, response, BUFFER_SIZE)) {
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

    /* ---------- OPERATION PHASE: openRead ---------- */

    printf("Enter the file name to read from the server: ");
    scanf("%255s", filename);

    /* The filename is sent in Base64: (CM,openRead,<base64 name>) */
    base64_encode(filename, strlen(filename), encoded_name);

    strcpy(request, "(CM,openRead,");
    strcat(request, encoded_name);
    strcat(request, ")");

    if (!send_packet(socket_fd, request)) {
        printf("Could not send the openRead packet.\n");
        close(socket_fd);
        return 1;
    }

    printf("Sent: %s\n", request);

    /* The reply is (DP,<base64 data>) or (EE,code,<base64 description>) */
    if (!receive_packet(socket_fd, response, BUFFER_SIZE)) {
        printf("Could not receive the file (it may be too large).\n");
        close(socket_fd);
        return 1;
    }

    /* Remove the closing ')' so only the Base64 text is left */
    response[strlen(response) - 1] = '\0';

    if (strncmp(response, "(DP,", 4) == 0) {
        /* response + 4 points to the text after "(DP," */
        base64_decode(response + 4, file_data);

        printf("----- %s -----\n", filename);
        printf("%s\n", file_data);
        printf("-----------------\n");

        /* The server then sends (SC,READ_COMPLETE) */
        receive_packet(socket_fd, response, BUFFER_SIZE);
    }
    else if (strncmp(response, "(EE,", 4) == 0) {
        /* (EE,2,<base64>): the code is at index 4, the description starts at 6 */
        base64_decode(response + 6, file_data);
        printf("Server error %c: %s\n", response[4], file_data);
    }
    else {
        printf("Unexpected reply: %s\n", response);
    }

    /* ---------- CLOSING PHASE ---------- */

    /* Ask the server to close the connection */
    if (!send_packet(socket_fd, "(End)")) {
        printf("Could not send the End packet.\n");
        close(socket_fd);
        return 1;
    }

    printf("Sent: (End)\n");

    /* Receive the closing acknowledgement */
    if (!receive_packet(socket_fd, response, BUFFER_SIZE)) {
        printf("Could not receive the closing response.\n");
        close(socket_fd);
        return 1;
    }

    printf("Received: %s\n", response);

    close(socket_fd);

    printf("Connection closed.\n");

    return 0;
}
