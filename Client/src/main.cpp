#include <iostream>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "seal/seal.h" 
//#include "seal/seal.h"

//using namespace seal;

void send_public_key(const std::string& ip_address, int port) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[4096] = {0};
      

    // Creazione del descrittore del socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Converti l'indirizzo IP
    if (inet_pton(AF_INET, ip_address.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return;
    }

    // Connessione al server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed" << std::endl;
        return;
    }

    // Lettura della chiave pubblica
   // std::ifstream public_key_file("public_key.dat", std::ios::binary);
   // if (public_key_file.is_open()) {
    //    public_key_file.read(buffer, sizeof(buffer));
    //    ssize_t len = public_key_file.gcount();
    
        send(sock, "1234", 4, 0);
    //    std::cout << "Chiave pubblica inviata con successo" << std::endl;
    //} else {
        std::cout << "Chiave pubblica non inviata con successo" << std::endl;

    //}

    close(sock);
}

int main() {
    send_public_key("127.0.0.1", 11111); // Indirizzo IP e porta del server
    return 0;
}