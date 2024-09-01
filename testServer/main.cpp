#include <iostream>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include "seal/seal.h"
/*
//using namespace seal;
// AES_BLOCK_SIZE è 16 bytes, che è la dimensione della chiave per AES-128
using namespace seal;
using namespace std;

unsigned char key[AES_BLOCK_SIZE];
int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[4096] = {0};

void print_hex(const unsigned char* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

void generate_aes_128_key(unsigned char key[AES_BLOCK_SIZE]) {
    for (char i=0; i<=AES_BLOCK_SIZE-1; i++){
        key[i]=i;
    } 
    /*if (!RAND_bytes(key, AES_BLOCK_SIZE)) {
        std::cerr << "Error generating random bytes." << std::endl;
        exit(EXIT_FAILURE);
    } 
}

void start_server(int port){
    

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
}

void receive() {
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




    stringstream parms_stream;
    stringstream data_stream;
    stringstream sk_stream;

void first_step(){
  
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 30, 50 }));
        auto size = parms.save(parms_stream);
        cout << "EncryptionParameters: wrote " << size << " bytes" << endl;
        cout << "EncryptionParameters: data size upper bound (compr_mode_type::none): "
             << parms.save_size(compr_mode_type::none) << endl;
        cout << "             "
             << "EncryptionParameters: data size upper bound (compression): "
             << parms.save_size(/* Serialization::compr_mode_default ) << endl;

        vector<seal_byte> byte_buffer(static_cast<size_t>(parms.save_size()));
        parms.save(reinterpret_cast<seal_byte *>(byte_buffer.data()), byte_buffer.size());
        EncryptionParameters parms2;
        parms2.load(reinterpret_cast<const seal_byte *>(byte_buffer.data()), byte_buffer.size());
        cout << "EncryptionParameters: parms == parms2: " << boolalpha << (parms == parms2) << endl;
    
}
void second_step(){

    {
        EncryptionParameters parms;
        parms.load(parms_stream);
        parms_stream.seekg(0, parms_stream.beg);
        SEALContext context(parms);

        Evaluator evaluator(context);

        /*
        Next we need to load relinearization keys and the ciphertexts from our
        data_stream.
        
        RelinKeys rlk;
        Ciphertext encrypted1, encrypted2;

        /*
        Deserialization is as easy as serialization.
        
        rlk.load(context, data_stream);
        encrypted1.load(context, data_stream);
        encrypted2.load(context, data_stream);

        /*
        Compute the product, rescale, and relinearize.
        
        Ciphertext encrypted_prod;
        evaluator.multiply(encrypted1, encrypted2, encrypted_prod);
        evaluator.relinearize_inplace(encrypted_prod, rlk);
        evaluator.rescale_to_next_inplace(encrypted_prod);

        data_stream.seekp(0, parms_stream.beg);
        data_stream.seekg(0, parms_stream.beg);
        auto size_encrypted_prod = encrypted_prod.save(data_stream);

        print_line(__LINE__);
        cout << "Ciphertext (secret-key): wrote " << size_encrypted_prod << " bytes" << endl;
    }

    /*
    In the final step the client decrypts the result.
    
    {
        EncryptionParameters parms;
        parms.load(parms_stream);
        parms_stream.seekg(0, parms_stream.beg);
        SEALContext context(parms);

        /*
        Load back the secret key from sk_stream.
        
        SecretKey sk;
        sk.load(context, sk_stream);
        Decryptor decryptor(context, sk);
        CKKSEncoder encoder(context);

        Ciphertext encrypted_result;
        encrypted_result.load(context, data_stream);

        Plaintext plain_result;
        decryptor.decrypt(encrypted_result, plain_result);
        vector<double> result;
        encoder.decode(plain_result, result);

        print_line(__LINE__);
        cout << "Decrypt the loaded ciphertext" << endl;
        cout << "    + Expected result:" << endl;
        vector<double> true_result(encoder.slot_count(), 2.3 * 4.5);
        print_vector(true_result, 3, 7);

        cout << "    + Computed result ...... Correct." << endl;
        print_vector(result, 3, 7);
    }


    Plaintext pt("1x^2 + 3");
    stringstream stream;
    auto data_size = pt.save(stream);

    Serialization::SEALHeader header;
    Serialization::LoadHeader(stream, header);
    cout << "Size written to stream: " << data_size << " bytes" << endl;
    cout << "             "
         << "Size indicated in SEALHeader: " << header.size << " bytes" << endl;
    cout << endl;
#endif

}

int main() {  
   cout << "Sto funzionando" << endl;
    start_server(11111);

    first_step();
    // Genera una chiave AES-128 casuale
    generate_aes_128_key(key);
    print_hex(key, AES_BLOCK_SIZE);
  
    receive(); // Porta di ascolto
    return 0;
}
*/



/*

#include "seal/seal.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

using namespace std;
using namespace seal;

void server_function(int client_socket)
{
    stringstream parms_stream;
    stringstream data_stream;

    // Configura i parametri di crittografia
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 50}));

    // Serializza e invia i parametri al client
    auto size = parms.save(parms_stream);
    cout << "EncryptionParameters: wrote " << size << " bytes" << endl;
    string serialized_parms = parms_stream.str();
    cout << "serialized_parms " << serialized_parms  << endl;
    send(client_socket, serialized_parms.data(), serialized_parms.size(), 0);

    // Ricevi la chiave pubblica e le chiavi di relinearizzazione dal client
    char buffer[1000000];
    int received_bytes = recv(client_socket, buffer, sizeof(buffer), 0);
    data_stream.write(buffer, received_bytes);


    RelinKeys rlk;
    PublicKey pk;
   

    SEALContext context(parms);
    Evaluator evaluator(context);
   // rlk.load(context, parms_stream);
   // pk.load(context, parms_stream);

    rlk.load(context, data_stream);
    pk.load(context, data_stream);
    // Ricevi i dati cifrati dal client
    Ciphertext encrypted1, encrypted2;
    received_bytes = recv(client_socket, buffer, sizeof(buffer), 0);
    data_stream.write(buffer, received_bytes);
    //CRASHA QUA
    string chipersetfromclient = data_stream.str();
    cout << "chipersetfromclient " << chipersetfromclient  << endl;
    encrypted1.load(context, data_stream);
    encrypted2.load(context, data_stream);

    // Esegui moltiplicazione cifrata, rilinarizzazione e riscalatura
    Ciphertext encrypted_prod;
    evaluator.multiply(encrypted1, encrypted2, encrypted_prod);
    evaluator.relinearize_inplace(encrypted_prod, rlk);
    evaluator.rescale_to_next_inplace(encrypted_prod);

    // Invia il risultato cifrato al client

    //stringstream result_stream;
    data_stream.seekp(0, parms_stream.beg);
    data_stream.seekg(0, parms_stream.beg);
    encrypted_prod.save(data_stream);
    string serialized_result = data_stream.str();
    send(client_socket, serialized_result.data(), serialized_result.size(), 0);

    close(client_socket);
}*/
using namespace std;
using namespace seal;

//TERZA VERSIONE
  /*
    The server first determines the computation and sets encryption parameters
    accordingly.
    */
    void server_function(int client_socket){
        
        stringstream parms_stream;
        stringstream data_stream;
        stringstream sk_stream;

        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        cout<< CoeffModulus::MaxBitCount(1024)<< endl;
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 30, 50 }));

        /*
        Serialization of the encryption parameters to our shared stream is very
        simple with the EncryptionParameters::save function.
        */
        auto size = parms.save(parms_stream);

        /*
        The return value of this function is the actual byte count of data written
        to the stream.
        */
       // print_line(__LINE__);
        cout << "EncryptionParameters: wrote " << size << " bytes" << endl;

        /*
        Before moving on, we will take some time to discuss further options in
        serialization. These will become particularly important when the user
        needs to optimize communication and storage sizes.

        It is possible to enable or disable compression for serialization by
        providing EncryptionParameters::save with the desired compression mode as
        in the following examples:

            auto size = parms.save(shared_stream, compr_mode_type::none);
            auto size = parms.save(shared_stream, compr_mode_type::zlib);
            auto size = parms.save(shared_stream, compr_mode_type::zstd);

        If Microsoft SEAL is compiled with Zstandard or ZLIB support, the default
        is to use one of them. If available, Zstandard is preferred over ZLIB due
        to its speed.

        Compression can have a substantial impact on the serialized data size,
        because ciphertext and key data consists of many uniformly random integers
        modulo the coeff_modulus primes. Especially when using CKKS, the primes in
        coeff_modulus can be relatively small compared to the 64-bit words used to
        store the ciphertext and key data internally. Serialization writes full
        64-bit words to the destination buffer or stream, possibly leaving in many
        zero bytes corresponding to the high-order bytes of the 64-bit words. One
        convenient way to get rid of these zeros is to apply a general-purpose
        compression algorithm on the encrypted data. The compression rate can be
        significant (up to 50-60%) when using CKKS with small primes.
        */

        /*
        It is also possible to serialize data directly to a buffer. For this, one
        needs to know an upper bound for the required buffer size, which can be
        obtained using the EncryptionParameters::save_size function. This function
        also accepts the desired compression mode, or uses the default option
        otherwise.

        In more detail, the output of EncryptionParameters::save_size is as follows:

            - Exact buffer size required for compr_mode_type::none;
            - Upper bound on the size required for compr_mode_type::zlib or
              compr_mode_type::zstd.

        As we can see from the print-out, the sizes returned by these functions
        are significantly larger than the compressed size written into the shared
        stream in the beginning. This is normal: compression yielded a significant
        improvement in the data size, however, it is impossible to know ahead of
        time the exact size of the compressed data. If compression is not used,
        then the size is exactly determined by the encryption parameters.
        */
      //  print_line(__LINE__);
        cout << "EncryptionParameters: data size upper bound (compr_mode_type::none): "
             << parms.save_size(compr_mode_type::none) << endl;
        cout << "             "
             << "EncryptionParameters: data size upper bound (compression): "
             << parms.save_size(/* Serialization::compr_mode_default */) << endl;

        /*
        As an example, we now serialize the encryption parameters to a fixed size
        buffer.
        */
        vector<seal_byte> byte_buffer(static_cast<size_t>(parms.save_size()));
        parms.save(reinterpret_cast<seal_byte *>(byte_buffer.data()), byte_buffer.size());

        /*
        To illustrate deserialization, we load back the encryption parameters
        from our buffer into another instance of EncryptionParameters. Note how
        EncryptionParameters::load in this case requires the size of the buffer,
        which is larger than the actual data size of the compressed parameters.
        The serialization format includes the true size of the data and the size
        of the buffer is only used for a sanity check.
        */
        EncryptionParameters parms2;
        parms2.load(reinterpret_cast<const seal_byte *>(byte_buffer.data()), byte_buffer.size());

        /*
        We can check that the saved and loaded encryption parameters indeed match.
        */
        //print_line(__LINE__);
        cout << "EncryptionParameters: parms == parms2: " << boolalpha << (parms == parms2) << endl;

        /*
        The functions presented and used here exist for all Microsoft SEAL objects
        that are meaningful to serialize. However, it is important to understand
        more advanced techniques that can be used for further compressing the data
        size. We will present these techniques below.
        */
    SEALContext context(parms);  
    string serialized_parms2 = parms_stream.str();
    //cout << "serialized_parms " << serialized_parms  << endl;
    send(client_socket, serialized_parms2.data(), serialized_parms2.size(), 0);
     cout << "Ho funzionato? " << endl;
    // Ricevi i dati dal client
    char buffer[500000];
    int received_bytes2 = recv(client_socket, buffer, sizeof(buffer), 0);
    data_stream.write(buffer, received_bytes2);

    
    Evaluator evaluator(context);
 /*
        Next we need to load relinearization keys and the ciphertexts from our
        data_stream.
        */
        RelinKeys rlk;
        Ciphertext encrypted1, encrypted2;

        /*
        Deserialization is as easy as serialization.
        */
        data_stream.seekg(0, data_stream.cur);
       // string serialized_data3 = data_stream.str();
        rlk.load(context, data_stream);
        encrypted1.load(context, data_stream);
        encrypted2.load(context, data_stream);

        /*
        Compute the product, rescale, and relinearize.
        */
        Ciphertext encrypted_prod;
        evaluator.multiply(encrypted1, encrypted2, encrypted_prod);
        evaluator.relinearize_inplace(encrypted_prod, rlk);
        evaluator.rescale_to_next_inplace(encrypted_prod);

        /*
        we use data_stream to communicate encrypted_prod back to the client.
        there is no way to save the encrypted_prod as a seeded object: only
        freshly encrypted secret-key ciphertexts can be seeded. Note how the
        size of the result ciphertext is smaller than the size of a fresh
        ciphertext because it is at a lower level due to the rescale operation.
        */
        data_stream.seekp(0, parms_stream.beg);
        data_stream.seekg(0, parms_stream.beg);
        auto size_encrypted_prod = encrypted_prod.save(data_stream);

      //  print_line(__LINE__);
        cout << "Ciphertext (secret-key): wrote " << size_encrypted_prod << " bytes" << endl;
      
      string serialized_data = parms_stream.str();
    //cout << "serialized_data " << serialized_data  << endl;
    send(client_socket, serialized_data.data(), serialized_data.size(), 0);
    }

/*
int main()
{   
    int server_fd, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Creazione del socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8084);

    // Associa il socket alla porta
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Metti in ascolto il socket
    if (listen(server_fd, 3) < 0)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    // Accetta la connessione dal client
    if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
    {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }

    // Funzione del server
    server_function(client_socket);

    return 0;
}

*/
  
//FINE TERZA VERSIONE
  


  int main(){

  }