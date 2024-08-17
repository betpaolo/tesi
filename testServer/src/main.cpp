#include <iostream>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
//#include "seal/seal.h"

//using namespace seal;

void receive_public_key(int port) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[4096] = {0};

    // Creazione del descrittore del socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Attacco del socket al numero di porta
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // Ricezione della chiave pubblica
    ssize_t valread = read(new_socket, buffer, sizeof(buffer));
    if (valread > 0) {
        std::ofstream public_key_file("received_public_key.dat", std::ios::binary);
        public_key_file.write(buffer, valread);
        public_key_file.close();
        std::cout << "Chiave pubblica ricevuta e salvata con successo" << std::endl;
    }

    close(new_socket);
    close(server_fd);
}

int main() {
    std::cout << "Sto funzionando" << std::endl;
    receive_public_key(11111); // Porta di ascolto
    return 0;
}
