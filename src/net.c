#include "net.h"

uint8_t hmc_serve(uint16_t port) {
    int server_fd, new_socket;
    socklen_t addrlen = sizeof(address);
    char* hello = "Hello from server";

    int32_t fd;

    /// TODO: Support ipv6
    ENEG((fd = socket(AF_INET, SOCK_STREAM, 0)), "Could not create port! %m");

    int opt = 1;
    ENEG(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    ENEG(bind(fd, (struct sockaddr*)&addr, sizeof(addr)), "Could not bind socket to port %u!", port);
    ENEG(listen(fd, 1), "Could not set up socket to listen!");
    int32_t remote_fd;
    ENEG((remote_fd = accept(remote_fd, (struct sockaddr*)&addr, &addrl));
  
    ssize_t readlen;
    char buffer[1024] = { 0 };
    ENEG((readlen = read(remote_fd, buffer, ARRAY_LEN(buffer))))
    printf("%s\n", buffer);
    send(new_socket, hello, strlen(hello), 0);
    printf("Hello message sent\n");

    // closing the connected socket
    close(new_socket);
  
    // closing the listening socket
    close(server_fd);
    return 0;
}
  listen(port, 1);
}

uint8_t hmc_connect(char *ip, uint16_t port) {

}
