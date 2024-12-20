#include <stdio.h>
#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include "openssl/evp.h"
#include <fstream>
#include <cstdlib>  // per la funzione system
#include "seal/seal.h"
#include "seal/util/uintcore.h"
#include <thread> 
#include <iomanip>



using namespace std;
using namespace seal;

#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include "cryptopp/elgamal.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"




void elGamal() {
    using namespace CryptoPP;
    // Generatore di numeri casuali
    AutoSeededRandomPool rng;

    // 1. Generazione delle chiavi ElGamal
    ElGamalKeys::PrivateKey privateKey;
    ElGamalKeys::PublicKey publicKey;

    // Lunghezza chiave 2048 bit
    privateKey.GenerateRandomWithKeySize(rng, 2048);
    privateKey.MakePublicKey(publicKey);

    // 2. Messaggio da cifrare
    std::string plainText = "Messaggio segreto da cifrare con ElGamal";

    // Cifratura
std::vector<uint8_t> plainText = {0x01, 0x02, 0x03, 0x04};  // Esempio di dati binari
std::vector<uint8_t> cipherText;

StringSource(packet.data(), plainText.size(), true,
    new PK_EncryptorFilter(rng, encryptor,
        new VectorSink(cipherText)));


// Generatore casuale
    AutoSeededRandomPool rng;

    // Genera chiavi ElGamal
    ElGamal::Decryptor decryptor;
    decryptor.AccessKey().GenerateRandomWithKeySize(rng, 2048);
    ElGamal::Encryptor encryptor(decryptor);

    // Dati da cifrare (vettore di uint8_t)
    std::vector<uint8_t> plainText = {0x01, 0x02, 0x03, 0x04};  // Dati binari
    std::vector<uint8_t> cipherText;

    // Cifratura
    StringSource(plainText.data(), plainText.size(), true,
        new PK_EncryptorFilter(rng, encryptor, new VectorSink(cipherText)));




    std::string cipherText;
    ElGamalEncryptor encryptor(publicKey);
    StringSource(plainText, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(cipherText)));

    // Mostra il ciphertext in formato esadecimale
    std::string encoded;
    StringSource(cipherText, true, new HexEncoder(new StringSink(encoded)));
    std::cout << "Messaggio cifrato: " << encoded << std::endl;

    // 3. Decifratura
    std::string recoveredText;
    ElGamalDecryptor decryptor(privateKey);
    StringSource(cipherText, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(recoveredText)));

    // Mostra il messaggio decifrato
    std::cout << "Messaggio decifrato: " << recoveredText << std::endl;

   
}


// Funzione per generare dati casuali
std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    std::generate(data.begin(), data.end(), [&](){ return dis(gen); });
    return data;
}
// -------------------------------ADAPTATION FUNCTIONS---------------------------------
std::vector<double> convertToDouble(const std::vector<uint8_t> &input)
{
    std::vector<double> result;
    result.reserve(input.size());  // Alloca spazio per evitare riallocazioni durante l'inserimento

    // Converte ogni elemento del vector uint8_t in double e lo aggiunge a result
    for (auto byte : input)
    {
        result.push_back(static_cast<double>(byte));
    }

    return result;
}

std::uint64_t vector_to_uint64(const std::vector<uint8_t>& plaintext) {
    std::uint64_t result = 0;

    // Assicurati che il numero di byte non superi 8, poiché uint64_t è di 8 byte.
    std::size_t size = std::min(plaintext.size(), static_cast<std::size_t>(8));

    // Combina i byte nel uint64_t, dal byte più significativo al meno significativo.
    for (std::size_t i = 0; i < size; ++i) {
        result |= static_cast<std::uint64_t>(plaintext[i]) << (8 * i);
    }

    return result;
}

char buffer[100];
// Funzione per aggiornare il buffer con l'ora corrente
void updateTime(char* buffer, std::size_t bufferSize) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) % 1000000;
    std::tm* local_time = std::localtime(&now_c);
    
    // Formatta l'ora corrente nel buffer
    std::strftime(buffer, bufferSize, "%H:%M:%S", local_time);
    
    // Aggiungi i microsecondi al buffer
    snprintf(buffer + std::strlen(buffer), bufferSize - std::strlen(buffer), ".%06ld", microseconds.count());
}

//----------------------------CRYPTOGRAPHY FUNCTIONS----------------------------

// AES Function
std::vector<uint8_t> aes_encrypt256(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}




// SEAL (BGV)

void seal_encrypt_bfv(const std::vector<uint8_t>& plaintext) {

    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    
    SEALContext context(parms);
   
    KeyGenerator keygen(context);
    cout<< "-----------------------------------------------------------"<<endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Inizio Generazione Chiavi BFV" << buffer << std::endl;
    SecretKey secret_key = keygen.secret_key();
    cout<< "-----------------------------------------------------------" <<endl;

    PublicKey public_key;
    keygen.create_public_key(public_key);
     cout << "Dimensione chiave pubblica " << public_key.data().size() << endl;
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    updateTime(buffer, sizeof(buffer));
    cout<< "-----------------------------------------------------------"<<endl;
    std::cout << "Fine Generazione Chiavi BFV" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;

    cout << "Dimensione chiave Relin " << relin_keys.data().size() << endl;
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    // Conversione dei 20 byte in uint64_t per il batch encoder
    for (size_t i = 0; i < plaintext.size(); i++) {
        pod_matrix[i] = static_cast<uint64_t>(plaintext[i]);
    }
   
    cout << "Input plaintext matrix:" << endl;
   
    Plaintext plain_matrix;
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    Ciphertext encrypted_matrix;
  
    cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    updateTime(buffer, sizeof(buffer));
    cout<< "-----------------------------------------------------------"<<endl;

    std::cout << "Timing Fine encryption" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;

    stringstream data_stream;
    encrypted_matrix.save(data_stream);
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing Fine serializzazione" << buffer << std::endl;
    size_t ciphertext_size_bytes = encrypted_matrix.size() * poly_modulus_degree * parms.coeff_modulus().size() * sizeof(uint64_t);
    std:cout<<"Dimensione chipertext"<<ciphertext_size_bytes<<endl;
}

// SEAL (CKKS)

void seal_encrypt_ckks(const std::vector<uint8_t>& plaintext) {
  
   vector<double> input= convertToDouble(plaintext);
   EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 4096;
    cout<< CoeffModulus::MaxBitCount(4096)<< "Max bit"<< endl;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30,20,20,30}));
    cout<< "-----------------------------------------------------------"<<endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing Inizio Generazione chiavi CKKS" << buffer << std::endl; 
    std:cout<< "-----------------------------------------------------------"<<endl;  
    SEALContext context(parms);

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
cout<< "-----------------------------------------------------------"<<endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing Fine Generazione chiavi CKKS" << buffer << std::endl;  
cout<< "-----------------------------------------------------------"<<endl;
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    
    cout << "Input vector: " << endl;
   
    Plaintext plain;
    double scale = pow(2.0, 30); //Il parametro scale in CKKS è fondamentale per controllare la precisione e l'accuratezza delle operazioni aritmetiche sui dati cifrati. La scelta del valore di scale dipende dal tipo di operazioni previste, dalla precisione necessaria, e dal modulo coefficiente disponibile

    cout << "Encode input vector." << endl;
    encoder.encode(input, scale, plain);

    
    vector<double> output;


    Ciphertext encrypted;
    cout << "Encrypt input vector, square, and relinearize." << endl;
    encryptor.encrypt(plain, encrypted);
    cout<< "-----------------------------------------------------------"<<endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing Fine Crittografia CKKS" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;
 //FINE CRITTOGRAFIA
  
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);

  
    cout << "    + Scale in squared input: " << encrypted.scale() << " (" << log2(encrypted.scale()) << " bits)"
         << endl;

    cout << "Decrypt and decode." << endl;
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, output);
    cout << "    + Result vector ...... Correct." << endl;
  

    
}


void seal_encrypt_ckks_normal(const std::vector<uint8_t>& plaintext) {

   
}





 //FINE CRITTOGRAFIA
  
   // evaluator.square_inplace(encrypted);
    //evaluator.relinearize_inplace(encrypted, relin_keys);

  
   // cout << "    + Scale in squared input: " << encrypted.scale() << " (" << log2(encrypted.scale()) << " bits)"
   //      << endl;


 //   cout << "Decrypt and decode." << endl;
 //   decryptor.decrypt(encrypted, plain);
 //   encoder.decode(plain, output);
 //   cout << "    + Result vector ...... Correct." << endl;
  
   


void encapsulate_packet(size_t packet_size) {
cout<< "-----------------------------------------------------------"<<endl;
updateTime(buffer, sizeof(buffer));
std::cout << "Timing " << buffer << std::endl;
cout<< "-----------------------------------------------------------"<<endl;
// Generazione dati casuali
    std::vector<uint8_t> data = generate_random_data(packet_size);
//----------------------------------------AES-----------------------------------------
    // Avvio script misure AES - CHIAVI    
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing " << buffer << std::endl;

    auto start= std::chrono::high_resolution_clock::now();
    //std::thread pythonThread(startPythonScript);
    // Chiavi e IV per AES
    std::vector<uint8_t> key(16);  // AES-128, per AES-256 utilizzare 32
    std::vector<uint8_t> iv(16);   // IV
    std::generate(key.begin(), key.end(), [](){ return rand() % 256; });
    std::generate(iv.begin(), iv.end(), [](){ return rand() % 256; });
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing Fine Generazione chiavi AES" << buffer << std::endl;
    //Inizio encryption AES
    std::vector<uint8_t> aes_ciphertext = aes_encrypt(data, key, iv);
    std::cout << "AES encryption complete. Ciphertext size: " << aes_ciphertext.size() << std::endl; 
    // Termina la misurazione del tempo
    auto end = std::chrono::high_resolution_clock::now(); 
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing Fine AES" << buffer << std::endl;
  
    // Calcola la durata
//-----------------------------------------------------------------------------------
    std::chrono::duration<double> duration = end - start;
    // Stampa il tempo trascorso
    std::cout << "Tempo trascorso: " << duration.count() << " secondi" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing crittografia omomorfica BFV" << buffer << std::endl;
    // Crittografia Omomorfica (BFV)
   auto start2 = std::chrono::high_resolution_clock::now();
// seal_encrypt_bfv(data);
    
   
auto end2 = std::chrono::high_resolution_clock::now();
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing Fine crittografia BFV" << buffer << std::endl;
    std::chrono::duration<double> duration2 = end2 - start2;
    std::cout << "Tempo trascorso: " << duration2.count() << " secondi" << std::endl;


//----------------------------------------------------------------------------------    
    auto start3 = std::chrono::high_resolution_clock::now();
    seal_encrypt_ckks(data);
    auto end3 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration3 = end3 - start3;
    std::cout << "Tempo trascorso CKKS: " << duration3.count() << " secondi" << std::endl;
auto start4 = std::chrono::high_resolution_clock::now();
seal_encrypt_ckks_normal(data);
auto end4 = std::chrono::high_resolution_clock::now();
std::chrono::duration<double> duration4 = end4 - start4;
    std::cout << "Tempo trascorso CKKS: " << duration4.count() << " secondi" << std::endl;
}

int main() {
    size_t packet_size = 8; // Dimensione del pacchetto
    elGamal();
    encapsulate_packet(packet_size);
    return 0;
}












































/*
std::atomic<bool> running(true); // Variabile per gestire l'esecuzione del processo
pid_t pythonPid = -1;  // Variabile per il PID del processo Python

void startPythonScript() {
    // Usa popen per avviare lo script Python e ottenere il PID
    FILE* pipe = popen("python3 autoGainTimeExportAes.py & echo $!", "r"); // Modifica con il percorso corretto
    if (!pipe) {
        std::cerr << "Errore: impossibile avviare il programma Python." << std::endl;
        return;
    }

    // Leggi il PID del processo Python
    fscanf(pipe, "%d", &pythonPid);
    pclose(pipe);

    std::cout << "Programma Python avviato con PID: " << pythonPid << std::endl;

    // Attendi finché "running" è vero
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1)); // Attesa passiva
    }

    // Se "running" diventa false, termina il processo Python
    if (pythonPid > 0) {
        std::cout << "Terminazione del programma Python con PID: " << pythonPid << std::endl;
        std::string killCommand = "kill " + std::to_string(pythonPid);
        std::system(killCommand.c_str());
    }
}
*/