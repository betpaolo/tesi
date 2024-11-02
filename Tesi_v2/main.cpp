// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
#include "examples.h"
#include "openssl/evp.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include "cryptopp/elgamal.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#define GMPXX_USE_GMP_H
#include <gmpxx.h>
#include <fstream>  

extern "C" {
    #include <gmp.h>        // GMP header
    #include <paillier.h>   // Paillier header
} 

#define SENDING
#define SEAL_USE_ZSTD 
#define SEAL_USE_ZLIB
using namespace std;
using namespace seal;

char buffer[100];
//-- Update Time function
void updateTime(char* buffer, std::size_t bufferSize) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) % 1000000;
    std::tm* local_time = std::localtime(&now_c);
    std::strftime(buffer, bufferSize, "%H:%M:%S", local_time);
    // Add the microsecond
    snprintf(buffer + std::strlen(buffer), bufferSize - std::strlen(buffer), ".%06ld", microseconds.count());
}

static std::vector<uint8_t> packet;
std::vector<double> data_double;

void elGamal() {
    
   
  
        
    using namespace CryptoPP;
    AutoSeededRandomPool rng;
    updateTime(buffer, sizeof(buffer));
    cout<< "-----------------------------------------------------------"<<endl;
    std::cout << "Inizio Generazione Chiavi EL GAMAL" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;
    //ElGamal Key Generator
    ElGamalKeys::PrivateKey privateKey;
    ElGamalKeys::PublicKey publicKey;
    //2048 bit key length
    privateKey.GenerateRandomWithKeySize(rng, 2048);
    privateKey.MakePublicKey(publicKey);
    updateTime(buffer, sizeof(buffer));
    std::cout << "INIZIO crittografia EL GAMAL" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;
    std::vector<uint8_t> cipherText;
    // Encryption
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_encode_sum(0);
    int count =10;
     for (int i = 0; i < count; i++)
    {
    time_start = chrono::high_resolution_clock::now();
    ElGamalEncryptor encryptor(publicKey);
    StringSource(packet.data(), packet.size(), true,
        new PK_EncryptorFilter(rng, encryptor, new VectorSink(cipherText)));
    time_end = chrono::high_resolution_clock::now();
    time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    auto avg_encode = time_encode_sum.count() / count;
    std::cout << "Average El Gamal Encryption: " << avg_encode << "microseconds"<<  std::endl;
   // std::string encoded;
   // StringSource(cipherText.data(), cipherText.size(), true,
   //  new HexEncoder(new StringSink(encoded)));
    std::cout << "Dimensione del messaggio cifrato: " << cipherText.size() << " byte" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Fine Crittografia EL GAMAL" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;
    // Decryption
    // std::vector<uint8_t> recoveredText;
    // ElGamalDecryptor decryptor(privateKey);
    //StringSource(cipherText.data(), cipherText.size(), true,
    //  new PK_DecryptorFilter(rng, decryptor, new VectorSink(recoveredText)));

}


void aes_encryption(int packetDimension) {
  
    long long count = 10;
    std::vector<uint8_t> key(16);  // AES-256, 16 per avere AES-128
    std::vector<uint8_t> iv(16);   // IV
    std::generate(key.begin(), key.end(), [](){ return rand() % 256; });
    std::generate(iv.begin(), iv.end(), [](){ return rand() % 256; });
    
    

    // Crea contesto
    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();
    if (!ctx_enc || !ctx_dec) {
        throw std::runtime_error("Errore nella creazione del contesto");
    }

    std::vector<uint8_t> ciphertext(packet.size() + EVP_MAX_BLOCK_LENGTH);
    std::vector<uint8_t> decryptedtext(packet.size() + EVP_MAX_BLOCK_LENGTH);

    int len, ciphertext_len;
    chrono::microseconds time_encode_sum(0), time_decode_sum(0);
    
    // Inizializzazione crittografia
    EVP_EncryptInit_ex(ctx_enc, EVP_aes_128_cbc(), nullptr, key.data(), iv.data());

    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing inizio crittografia AES " << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
    // Ciclo per cifratura
    for (int i = 1; i <= count; i++) {
        auto time_start = chrono::high_resolution_clock::now();
        EVP_EncryptUpdate(ctx_enc, ciphertext.data(), &len, packet.data(), packet.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx_enc, ciphertext.data() + len, &len);
        ciphertext_len += len;
        auto time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }

    auto avg_encode = time_encode_sum.count() / count;
    std::cout << "Average AES Encryption: " << avg_encode << " microseconds, with packet size: " << ciphertext_len << " and data length encrypted: " << packet.size() << std::endl;

    // Inizializzazione decifratura
    EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_cbc(), nullptr, key.data(), iv.data());
    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing inizio decifratura AES" << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
    int decrypted_len;
    for (int i = 1; i <= count; i++) {
        auto time_start = chrono::high_resolution_clock::now();
        EVP_DecryptUpdate(ctx_dec, decryptedtext.data(), &len, ciphertext.data(), ciphertext_len);
        decrypted_len = len;
        EVP_DecryptFinal_ex(ctx_dec, decryptedtext.data() + len, &len);
        decrypted_len += len;
        auto time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing fine decifratura AES" << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;

    auto avg_decode = time_decode_sum.count() / count;
    std::cout << "Average AES Decryption: " << avg_decode << " microseconds" << std::endl;

    // Scrivi dati su file
    std::ofstream file("encryption_data_aes.csv", std::ios::app);
    if (file.is_open()) {
        file << avg_encode << "," << ciphertext_len << ","  << avg_decode << ","<< "\n";
        file.close();
        std::cout << "Data saved to encryption_data_aes.csv" << std::endl;
    } else {
        std::cerr << "Error opening file!" << std::endl;
    }

    // Libera la memoria dei contesti
    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);

    

    
}

void generate_random_data(size_t size) {
    packet.resize(size);  // Assicurati che il vettore abbia una dimensione definita
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dis(0, 20);
    std::generate(packet.begin(), packet.end(), [&]() {
        return static_cast<uint8_t>(dis(gen)); // Converti il valore in uint8_t
    });
    
    // Stampa i dati generati
    //std::cout << "Generated Plaintext:" << std::endl;
    // for (const auto& num : packet) {
    //    std::cout << static_cast<int>(num) << " ";  // Cast per stampare come interi
    //}
    std::cout << std::endl;
}

paillier_plaintext_t* convert_vector_to_paillier_plaintext(const std::vector<uint8_t>& packet) {
    size_t len = packet.size();
    cout<<"dimension "<< len<< endl;
    void* byte_array = static_cast<void*>(const_cast<uint8_t*>(packet.data()));
    
    // Paillier plaintext
    paillier_plaintext_t* plaintext = paillier_plaintext_from_bytes(byte_array, len);
    
    return plaintext; 
}
/*
void  paillier() {
    paillier_plaintext_t* plaintext = convert_vector_to_paillier_plaintext(packet);
    int modulus_bits = 3072;
    paillier_pubkey_t *pubkey;
    paillier_prvkey_t *privkey;
    updateTime(buffer, sizeof(buffer));
    //cout<< "-----------------------------------------------------------"<<endl;
    //std::cout << "Inizio Generazione chiavi Pallier" << buffer << std::endl;
   // cout<< "-----------------------------------------------------------"<<endl;
    // Generate keys
    paillier_keygen(modulus_bits, &pubkey, &privkey, paillier_get_rand_devurandom);
    updateTime(buffer, sizeof(buffer));
    //cout<< "-----------------------------------------------------------"<<endl;
    //std::cout << "Fine Ch//iavi PALLIER" << buffer << std::endl;
    //cout<< "-----------------------------------------------------------"<<endl;
    // Output the size of the public key modulus (N) in bytes
    size_t pubkey_size = (size_t)mpz_sizeinbase(pubkey->n, 2); // Size in bits
    printf("Public Key Size (N): %zu bits, %zu bytes\n", pubkey_size, (pubkey_size + 7) / 8);
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    int count =10;
    paillier_ciphertext_t *ciphertext;
    
    for (int i = 0; i < count; i++)
    {
    time_start = chrono::high_resolution_clock::now();
    // Encrypt the plaintext
    ciphertext = paillier_enc(NULL, pubkey, plaintext, paillier_get_rand_devurandom);
    time_end = chrono::high_resolution_clock::now();
    time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    auto avg_encode = time_encode_sum.count() / count;
    std::cout << "Average paillier Encryption: " << avg_encode << "microseconds"<<  std::endl;


    // Output the size of the ciphertext
    size_t ciphertext_size = (size_t)mpz_sizeinbase(ciphertext->c, 2); // Size in bits
    printf("Ciphertext Size: %zu bits, %zu bytes\n", ciphertext_size, (ciphertext_size + 7) / 8);
    updateTime(buffer, sizeof(buffer));
    //cout<< "-----------------------------------------------------------"<<endl;
    //std::cout << "Fine Crittografia Pallier" << buffer << std::endl;
    //cout<< "-----------------------------------------------------------"<<endl;
paillier_plaintext_t *decrypted;
    for (int i = 0; i < count; i++) {
    // Decrypt the ciphertext
    time_start = chrono::high_resolution_clock::now();
    decrypted = paillier_dec(NULL, pubkey, privkey, ciphertext);
    time_end = chrono::high_resolution_clock::now();
    time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
}

auto avg_decode = time_decode_sum.count() / count;
std::cout << "Average Paillier Decryption: " << avg_decode << " microseconds" << std::endl;

// Output the size of the decrypted plaintext
size_t plaintext_size = (size_t)mpz_sizeinbase(decrypted->m, 2); // Size in bits
printf("Decrypted Plaintext Size: %zu bits, %zu bytes\n", plaintext_size, (plaintext_size + 7) / 8);

// Optionally compare the original and decrypted plaintexts
if (mpz_cmp(plaintext->m, decrypted->m) == 0) {
    std::cout << "Decryption successful, plaintext matches original." << std::endl;
} else {
    std::cout << "Error in decryption, plaintext does not match original." << std::endl;
}
        
} 
 
*/


void paillier() {

    paillier_plaintext_t* plaintext = convert_vector_to_paillier_plaintext(packet);
    int modulus_bits = 3072;
    paillier_pubkey_t *pubkey;
    paillier_prvkey_t *privkey;
    updateTime(buffer, sizeof(buffer));

    // Generazione delle chiavi
    paillier_keygen(modulus_bits, &pubkey, &privkey, paillier_get_rand_devurandom);
    updateTime(buffer, sizeof(buffer));

    size_t pubkey_size = (size_t)mpz_sizeinbase(pubkey->n, 2); // Dimensione in bit
    printf("Public Key Size (N): %zu bits, %zu bytes\n", pubkey_size, (pubkey_size + 7) / 8);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    int count = 10;

    paillier_ciphertext_t *ciphertext1, *ciphertext2, *sum_ciphertext;

    // Encryption del primo plaintext
    for (int i = 0; i < count; i++) {
        time_start = chrono::high_resolution_clock::now();
        ciphertext1 = paillier_enc(NULL, pubkey, plaintext, paillier_get_rand_devurandom);
        time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    auto avg_encode = time_encode_sum.count() / count;
    std::cout << "Average Paillier Encryption: " << avg_encode << " microseconds" << std::endl;

    size_t ciphertext_size = (size_t)mpz_sizeinbase(ciphertext1->c, 2); // Dimensione in bit
    printf("Ciphertext Size: %zu bits, %zu bytes\n", ciphertext_size, (ciphertext_size + 7) / 8);

    // Creazione di un secondo plaintext
    paillier_plaintext_t* plaintext2 = convert_vector_to_paillier_plaintext(packet);

    // Somma dei plaintext
    paillier_plaintext_t* expected_sum = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
    mpz_init(expected_sum->m);
    mpz_add(expected_sum->m, plaintext->m, plaintext2->m);

    // Encryption del secondo plaintext
    ciphertext2 = paillier_enc(NULL, pubkey, plaintext2, paillier_get_rand_devurandom);

    // Somma dei ciphertext
    sum_ciphertext = paillier_create_enc_zero();
    paillier_mul(pubkey, sum_ciphertext, ciphertext1, ciphertext2);

    // Decifratura della somma
    paillier_plaintext_t *decrypted_sum;
    for (int i = 0; i < count; i++) {
        time_start = chrono::high_resolution_clock::now();
        decrypted_sum = paillier_dec(NULL, pubkey, privkey, sum_ciphertext);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    auto avg_decode = time_decode_sum.count() / count;
    std::cout << "Average Paillier Decryption: " << avg_decode << " microseconds" << std::endl;

    // Confronto e stampa del risultato della somma
    if (mpz_cmp(decrypted_sum->m, expected_sum->m) == 0) {
        std::cout << "Sum operation verified successfully: decrypted_sum matches expected_sum." << std::endl;
    } else {
        std::cerr << "Sum operation failed: decrypted_sum does not match expected_sum." << std::endl;
    }

    // Stampa del risultato della somma
    char* decrypted_sum_str = mpz_get_str(NULL, 10, decrypted_sum->m);
    std::cout << "Decrypted sum: " << decrypted_sum_str << std::endl;
    free(decrypted_sum_str); // Libera la stringa allocata

    // Libera la memoria
    paillier_freepubkey(pubkey);
    paillier_freeprvkey(privkey);
    paillier_freeplaintext(plaintext);
    paillier_freeplaintext(plaintext2);
    paillier_freeplaintext(decrypted_sum);
    paillier_freeplaintext(expected_sum);
    paillier_freeciphertext(ciphertext1);
    paillier_freeciphertext(ciphertext2);
    paillier_freeciphertext(sum_ciphertext);
    /*
    // Converte il vettore in un plaintext per l'encryption
    paillier_plaintext_t* plaintext = convert_vector_to_paillier_plaintext(packet);
    int modulus_bits = 3072;
    paillier_pubkey_t *pubkey;
    paillier_prvkey_t *privkey;
    updateTime(buffer, sizeof(buffer));

    // Generazione chiavi
    paillier_keygen(modulus_bits, &pubkey, &privkey, paillier_get_rand_devurandom);
    updateTime(buffer, sizeof(buffer));

    // Stampa la dimensione della chiave pubblica
    size_t pubkey_size = (size_t)mpz_sizeinbase(pubkey->n, 2); // Dimensione in bit
    printf("Public Key Size (N): %zu bits, %zu bytes\n", pubkey_size, (pubkey_size + 7) / 8);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    int count = 10;

    paillier_ciphertext_t *ciphertext1, *ciphertext2, *sum_ciphertext;

    // Encryption del primo plaintext
    for (int i = 0; i < count; i++) {
        time_start = chrono::high_resolution_clock::now();
        ciphertext1 = paillier_enc(NULL, pubkey, plaintext, paillier_get_rand_devurandom);
        time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    auto avg_encode = time_encode_sum.count() / count;
    std::cout << "Average Paillier Encryption: " << avg_encode << " microseconds" << std::endl;

    // Stampa la dimensione del ciphertext
    size_t ciphertext_size = (size_t)mpz_sizeinbase(ciphertext1->c, 2); // Dimensione in bit
    printf("Ciphertext Size: %zu bits, %zu bytes\n", ciphertext_size, (ciphertext_size + 7) / 8);

    // Crea un secondo plaintext (identico o diverso, a seconda dei dati che vuoi usare per test)
    paillier_plaintext_t* plaintext2 = convert_vector_to_paillier_plaintext(packet); // Usa un secondo packet se diverso

    // Calcola la somma dei plaintext originali per confronto
    paillier_plaintext_t *expected_sum = paillier_plaintext_add(pubkey, plaintext, plaintext2);

    // Encryption del secondo plaintext
    ciphertext2 = paillier_enc(NULL, pubkey, plaintext2, paillier_get_rand_devurandom);

    // Somma (operazione di moltiplicazione Paillier tra ciphertext1 e ciphertext2)
    sum_ciphertext = paillier_create_enc_zero();  // Crea un ciphertext per la somma
    paillier_mul(pubkey, sum_ciphertext, ciphertext1, ciphertext2);

    // Decifratura della somma
    paillier_plaintext_t *decrypted_sum;
    for (int i = 0; i < count; i++) {
        time_start = chrono::high_resolution_clock::now();
        decrypted_sum = paillier_dec(NULL, pubkey, privkey, sum_ciphertext);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    auto avg_decode = time_decode_sum.count() / count;
    std::cout << "Average Paillier Decryption: " << avg_decode << " microseconds" << std::endl;

    // Confronta il risultato decifrato con la somma attesa
    if (mpz_cmp(decrypted_sum->m, expected_sum->m) == 0) {
        std::cout << "Sum operation verified successfully: decrypted_sum matches expected_sum." << std::endl;
    } else {
        std::cerr << "Sum operation failed: decrypted_sum does not match expected_sum." << std::endl;
    }

    // Libera la memoria
    paillier_freepubkey(pubkey);
    paillier_freeprvkey(privkey);
    paillier_freeplaintext(plaintext);
    paillier_freeplaintext(plaintext2);
    paillier_freeplaintext(decrypted_sum);
    paillier_freeplaintext(expected_sum);
    paillier_freeciphertext(ciphertext1);
    paillier_freeciphertext(ciphertext2);
    paillier_freeciphertext(sum_ciphertext);*/
}



// Function to calculate the error between original and decrypted vectors
double calculate_error(const vector<double>& original, const vector<double>& decrypted, int fieldFactor)
{


    if (original.size() != decrypted.size())
    {
        cout << "dimensioni original " <<original.size()<< "dimensioni decriptato " << decrypted.size() << endl;
        throw invalid_argument("Vectors must have the same size");
    }

    double error_sum = 0.0;
    for (size_t i = 0; i <= original.size(); i=i+fieldFactor)
    {
        error_sum += abs(original[i] - decrypted[i]);
    }

    return error_sum / original.size(); // Return the average error
} 

void ckks_encryption(SEALContext context, int dimension){
    
 chrono::high_resolution_clock::time_point time_start, time_end;
 std::ofstream file("encryption_data_ckks.csv", std::ios::app); // Usa 'app' per aggiungere righe

    //print_parameters(context);
    cout << "byte: "<< dimension<< endl;

    auto &parms = context.first_context_data()->parms();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    //cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    cout << "dimensione chiave secret_key: " << secret_key.save_size() << "dimensione chiave public_key: " << public_key.save_size()<< endl; 

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context.using_keyswitching())
    {
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context.first_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_galois_keys(gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }
    cout << "dimensione chiave relkin " << relin_keys.save_size() << "dimensione chiave galois " << gal_keys.save_size()<< endl; 

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_add_sum(0);
    chrono::microseconds time_multiply_sum(0);
    chrono::microseconds time_multiply_plain_sum(0);
    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_relinearize_sum(0);
    chrono::microseconds time_rescale_sum(0);
    chrono::microseconds time_rotate_one_step_sum(0);
    chrono::microseconds time_rotate_random_sum(0);
    chrono::microseconds time_conjugate_sum(0);
    chrono::microseconds time_serialize_sum(0);
#ifdef SEAL_USE_ZLIB
    chrono::microseconds time_serialize_zlib_sum(0);
#endif
#ifdef SEAL_USE_ZSTD
    chrono::microseconds time_serialize_zstd_sum(0);
#endif
    /*
    How many times to run the test?
    */
    long long count = 10;

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    size_t buf_sizeNone;
    size_t buf_sizeZLIB;
    size_t buf_sizeZstandard;
    for (size_t i = 0; i < dimension && i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    Plaintext plain2(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
    double scale = sqrt(static_cast<double>(parms.coeff_modulus().back().value()));
    ckks_encoder.encode(pod_vector, scale, plain2);
    Ciphertext encrypted(context);
    encryptor.encrypt(plain2, encrypted);

    cout << "Running tests ";
    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing inizio crittografia CKKS " << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
    for (long long i = 0; i < count; i++)
    {
        /*
        [Encoding]
        For scale we use the square root of the last coeff_modulus prime
        from parms.
        */
        Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
        /*

        */
        double scale = sqrt(static_cast<double>(parms.coeff_modulus().back().value()));
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.encode(pod_vector, scale, plain);
        time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        
        /*
        [Encryption]
        */
        
        time_start = chrono::high_resolution_clock::now();
        encryptor.encrypt(plain, encrypted);
        time_end = chrono::high_resolution_clock::now();
        time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    }
    std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing inizio decrittografia CKKS " << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
      for (long long i = 0; i < count; i++){  
         Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0); 
        /*
        [Decoding]
        */
        vector<double> pod_vector2(ckks_encoder.slot_count());
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.decode(plain2, pod_vector2);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        

        /*
        [Decryption]
        */
        Plaintext plain2(poly_modulus_degree, 0);
        time_start = chrono::high_resolution_clock::now();
        decryptor.decrypt(encrypted, plain2);
        time_end = chrono::high_resolution_clock::now();
        time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);


        /*
        [Serialize Ciphertext]
        */
        size_t buf_sizeNone = static_cast<size_t>(encrypted.save_size(compr_mode_type::none));
        vector<seal_byte> buf(buf_sizeNone);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_sizeNone, compr_mode_type::none);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#ifndef SEAL_USE_ZLIB
        /*
        [Serialize Ciphertext (ZLIB)]
        */
        buf_sizeZLIB = static_cast<size_t>(encrypted.save_size(compr_mode_type::zlib));
        buf.resize(buf_sizeZLIB);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_sizeZLIB, compr_mode_type::zlib);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zlib_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
#ifndef SEAL_USE_ZSTD
        /*
        [Serialize Ciphertext (Zstandard)]
        */
        buf_sizeZstandard = static_cast<size_t>(encrypted.save_size(compr_mode_type::zstd));
        buf.resize(buf_sizeZstandard);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_sizeZstandard, compr_mode_type::zstd);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zstd_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
        /*
        Print a dot to indicate progress.
        */
        cout << ".";
        cout.flush();
    }  
std::cout << "-----------------------------------------------------------" << std::endl;
    updateTime(buffer, sizeof(buffer));
    std::cout << "Timing FINE DECRITTOGRAFIA CKKS " << buffer << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
    cout << " Done" << endl << endl;
    cout.flush();

    auto avg_encode = time_encode_sum.count() / count;
    auto avg_decode = time_decode_sum.count() / count;
    auto avg_encrypt = time_encrypt_sum.count() / count;
    auto avg_decrypt = time_decrypt_sum.count() / count;
    auto avg_add = time_add_sum.count() / (3 * count);
    auto avg_multiply = time_multiply_sum.count() / count;
    auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
    auto avg_square = time_square_sum.count() / count;
    auto avg_relinearize = time_relinearize_sum.count() / count;
    auto avg_rescale = time_rescale_sum.count() / count;
    auto avg_rotate_one_step = time_rotate_one_step_sum.count() / (2 * count);
    auto avg_rotate_random = time_rotate_random_sum.count() / count;
    auto avg_conjugate = time_conjugate_sum.count() / count;
    auto avg_serialize = time_serialize_sum.count() / count;
#ifdef SEAL_USE_ZLIB
    auto avg_serialize_zlib = time_serialize_zlib_sum.count() / count;
#endif
#ifdef SEAL_USE_ZSTD
    auto avg_serialize_zstd = time_serialize_zstd_sum.count() / count;
#endif
    cout << "Average encode: " << avg_encode << " microseconds" << endl;
    cout << "Average decode: " << avg_decode << " microseconds" << endl;
    cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
    cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
    cout << "Average add: " << avg_add << " microseconds" << endl;
    cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
    cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
    cout << "Average square: " << avg_square << " microseconds" << endl;
    if (context.using_keyswitching())
    {
        cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
        cout << "Average rescale: " << avg_rescale << " microseconds" << endl;
        cout << "Average rotate vector one step: " << avg_rotate_one_step << " microseconds" << endl;
        cout << "Average rotate vector random: " << avg_rotate_random << " microseconds" << endl;
        cout << "Average complex conjugate: " << avg_conjugate << " microseconds" << endl;
    }
    cout << "Average serialize ciphertext: " << avg_serialize << " microseconds" << endl;
#ifdef SEAL_USE_ZLIB
    cout << "Average compressed (ZLIB) serialize ciphertext: " << avg_serialize_zlib << " microseconds" << endl;
#endif
#ifdef SEAL_USE_ZSTD
    cout << "Average compressed (Zstandard) serialize ciphertext: " << avg_serialize_zstd << " microseconds" << endl;
#endif
    cout.flush();
    auto totTimeEncryption = avg_encode+avg_encrypt+avg_serialize;
    auto totTimeDecryption = avg_decode+avg_decrypt;
   if (file.is_open()) {
        //file << totTimeEncryption  << "," << buf_sizeNone << ","<< buf_sizeZLIB<< "," << buf_sizeZstandard << ","  << dimension << "," <<totTimeDecryption<< "\n";
        file << totTimeEncryption   << ","<< buf_sizeZLIB<< "," << buf_sizeZstandard << ","  << dimension << "," <<totTimeDecryption<< "\n";

        file.close();
        std::cout << "Data saved to encryption_dataCkks.csv" << std::endl;
    } else {
        std::cerr << "Error opening file!" << std::endl;
    }
}


void ckks_variance(SEALContext context)
{
   
    chrono::high_resolution_clock::time_point time_start, time_end, time_start_variance, time_end_variance;

    //print_parameters(context);
    //cout << endl;
   
    updateTime(buffer, sizeof(buffer));
    cout<< "-----------------------------------------------------------"<<endl;
    std::cout << "Inizio generazione chiavi CKKS" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;
    auto &parms = context.first_context_data()->parms();
    size_t poly_modulus_degree = parms.poly_modulus_degree();
    // Step 2: Access and print the prime moduli (coefficient modulus primes)
    auto coeff_modulus = parms.coeff_modulus();
    cout << "Prime Modulus values used in the coefficient modulus: " << endl;
    
    for (const auto& prime : coeff_modulus)
    {
        cout << prime.value() << endl;
    }


    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context.using_keyswitching())
    {
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context.first_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_galois_keys(gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }
    updateTime(buffer, sizeof(buffer));
    cout<< "-----------------------------------------------------------"<<endl;
    std::cout << "Fine Crittografia CKKS" << buffer << std::endl;
    cout<< "-----------------------------------------------------------"<<endl;

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_variance(0);
    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_add_sum(0);
    chrono::microseconds time_multiply_sum(0);
    chrono::microseconds time_multiply_plain_sum(0);
    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_relinearize_sum(0);
    chrono::microseconds time_rescale_sum(0);
    chrono::microseconds time_rotate_one_step_sum(0);
    chrono::microseconds time_rotate_random_sum(0);
    chrono::microseconds time_conjugate_sum(0);
    chrono::microseconds time_serialize_sum(0);
#ifdef SEAL_USE_ZLIB
    chrono::microseconds time_serialize_zlib_sum(0);
#endif
#ifdef SEAL_USE_ZSTD
    chrono::microseconds time_serialize_zstd_sum(0);
#endif
    /*
    How many times to run the test?
    */
    long long count = 10;
    for (int i=1; i<=count; i++){
    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    int fieldFactor=1;
    int scaleFactor= 28;
    double householders=ckks_encoder.slot_count()/fieldFactor;
    double avegareFactor=  1/householders; 
    
    vector<double> average_vector;
    vector<double> average_vectorPos;//(ckks_encoder.slot_count(), 0.0);
   // vector<double> adjustScaleVector;
   int slot=0;
   cout<<"slot disponibili"<< ckks_encoder.slot_count()<<endl;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        if (i % fieldFactor == 0 && i<=householders*fieldFactor) {
        average_vector.push_back(-avegareFactor);
        average_vectorPos.push_back(avegareFactor);
        pod_vector.push_back(0.0005+i*0.0005); 
        slot++;
        }
        else
        {
        average_vectorPos.push_back(1.00);
        average_vector.push_back(1.00);
        pod_vector.push_back(1.00); 
        }

    }
    cout<<"slot usati: "<<slot<<endl;
       // Print the data
   // cout << "data: ";
    //for (double val : pod_vector)
    //{
     //   cout << val << " ";
    //}
    //cout<<endl;

    
   // for (long long i = 0; i < count; i++)
    //{
        /*
        [Encoding]
              */
        Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
        /*

        */
        double scale =  pow(2.0, scaleFactor);
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.encode(pod_vector, scale, plain);
        time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
       
        /*
        [Encryption]
        */
        Ciphertext encrypted(context);
        time_start = chrono::high_resolution_clock::now();
        encryptor.encrypt(plain, encrypted);
        time_end = chrono::high_resolution_clock::now();
        time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);


        /*
        [Add]
        */
      time_start_variance = chrono::high_resolution_clock::now();
        Ciphertext SumC = encrypted;
        Ciphertext encrypted2 = encrypted;
        time_start = chrono::high_resolution_clock::now();
        int rotation=0;
        for (int i=0; i<=ckks_encoder.slot_count()/fieldFactor-1; i++){
        evaluator.rotate_vector_inplace(encrypted, fieldFactor, gal_keys);
        evaluator.add_inplace(SumC, encrypted);
        rotation++;
        }
      //cout<<"rotazioni: "<< rotation<<endl;
        //MEDIA
        Plaintext plainAverage;
        Plaintext plainAveragePos;
        Ciphertext AverageNegated;
        ckks_encoder.encode(average_vector, scale, plainAverage);
        ckks_encoder.encode(average_vectorPos, scale, plainAveragePos);

        evaluator.multiply_plain(SumC, plainAverage, AverageNegated);   
        evaluator.relinearize_inplace(AverageNegated, relin_keys);

    evaluator.rescale_to_next_inplace(AverageNegated);
    
    Plaintext plainAverageN(poly_modulus_degree, 0);
       decryptor.decrypt(AverageNegated, plainAverageN);
        //vector<double> pod_vector4(ckks_encoder.slot_count());
        //ckks_encoder.decode(plainAverageN, pod_vector4); 
        //cout << "Average: ";
        //for (int i = 0; i <= householders-1; i++){
        //        cout << pod_vector4[i]<< " ";
        //
        //    }
//
        Ciphertext CSubstracted;
        
        AverageNegated.scale()=pow(2.0, scaleFactor);
        parms_id_type last_parms_id = AverageNegated.parms_id();
        evaluator.mod_switch_to_inplace(encrypted, last_parms_id);
        evaluator.add(encrypted, AverageNegated, CSubstracted);
        Ciphertext squared;
        evaluator.square(CSubstracted, squared);

        Plaintext plainSquared(poly_modulus_degree, 0);
        decryptor.decrypt(squared, plainSquared);
        //vector<double> pod_vectorSquared(ckks_encoder.slot_count());
        //ckks_encoder.decode(plainSquared, pod_vectorSquared); 
        
        //cout << "pod_vectorSquared: ";
        //for (int i = 0; i <= householders-1; i++){
       //         cout << pod_vectorSquared[i]<< " ";
        //
        //    }
        evaluator.relinearize_inplace(squared, relin_keys);
        evaluator.rescale_to_next_inplace(squared);
        squared.scale()=pow(2.0, scaleFactor);
        Ciphertext SumSquared = squared;
 
        //Plaintext plain3(poly_modulus_degree, 0);
        //decryptor.decrypt(squared, plain3);
        //vector<double> pod_vector3(ckks_encoder.slot_count());
        //ckks_encoder.decode(plain3, pod_vector3); 
        //cout << "Squared: ";
        //for (int i = 0; i <= householders-1; i++){
        //        cout << pod_vector3[i]<< " ";
        //
        //    }
  
        for (int i=0; i<=ckks_encoder.slot_count()/fieldFactor-1; i++){
        evaluator.rotate_vector_inplace(squared, fieldFactor, gal_keys);
        evaluator.add_inplace(SumSquared, squared);
        }
        Ciphertext Result;
        Ciphertext AveragePos;
        evaluator.mod_switch_to_inplace(plainAveragePos, SumSquared.parms_id());
        encryptor.encrypt(plainAveragePos, AveragePos);
        evaluator.multiply_inplace(SumSquared, AveragePos);
        evaluator.relinearize_inplace(SumSquared, relin_keys);
        time_end_variance = chrono::high_resolution_clock::now();
        /*
        [Decryption]
        */
        Plaintext plain2(poly_modulus_degree, 0);
        time_start = chrono::high_resolution_clock::now();
        decryptor.decrypt(SumSquared, plain2);
        time_end = chrono::high_resolution_clock::now();
        time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        
        

         /*
        [Decode]
        */
        vector<double> pod_vector2(ckks_encoder.slot_count());
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.decode(plain2, pod_vector2);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);  

         // Print the decrypted data
         /*
    cout << "Decrypted data: ";

    for (int i = 0; i <= householders-1; i=i+fieldFactor){
        cout << pod_vector2[i]<< " ";
  
    }
*/

    // Calculate and print the error
    // double error = calculate_error(pod_vector, pod_vector2, fieldFactor);
  //  cout << "Average error between original and decrypted data: " << error << endl;
        /*
        [Serialize Ciphertext]
        */
        size_t buf_size = static_cast<size_t>(encrypted.save_size(compr_mode_type::none));
        vector<seal_byte> buf(buf_size);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_size, compr_mode_type::none);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#ifdef SEAL_USE_ZLIB
        /*
        [Serialize Ciphertext (ZLIB)]
        */
        buf_size = static_cast<size_t>(encrypted.save_size(compr_mode_type::zlib));
        buf.resize(buf_size);
        cout <<"chipertext dimension using compression ZLIB: "<< buf_size <<endl;  
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_size, compr_mode_type::zlib);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zlib_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
#ifdef SEAL_USE_ZSTD
        /*
        [Serialize Ciphertext (Zstandard)]
        */
        buf_size = static_cast<size_t>(encrypted.save_size(compr_mode_type::zstd));
        buf.resize(buf_size);
        cout <<"chipertext dimension using compression ZSTD: "<< buf_size <<endl;
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_size, compr_mode_type::zstd);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zstd_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
         time_variance += chrono::duration_cast<chrono::microseconds>(time_end_variance - time_start_variance);
     }
    
    auto time_operation = time_variance.count()/count;
    auto avg_encode = time_encode_sum.count() / count;
    auto avg_decode = time_decode_sum.count() / count;
    auto avg_encrypt = time_encrypt_sum.count() / count;
    auto avg_decrypt = time_decrypt_sum.count() / count;
    auto avg_add = time_add_sum.count() / (3 * count);
    auto avg_multiply = time_multiply_sum.count() / count;
    auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
    auto avg_square = time_square_sum.count() / count;
    auto avg_relinearize = time_relinearize_sum.count() / count;
    auto avg_rescale = time_rescale_sum.count() / count;
    auto avg_rotate_one_step = time_rotate_one_step_sum.count() / (2 * count);
    auto avg_rotate_random = time_rotate_random_sum.count() / count;
    auto avg_conjugate = time_conjugate_sum.count() / count;
    auto avg_serialize = time_serialize_sum.count() / count;
#ifdef SEAL_USE_ZLIB
    auto avg_serialize_zlib = time_serialize_zlib_sum.count() / count;
#endif
#ifdef SEAL_USE_ZSTD
    auto avg_serialize_zstd = time_serialize_zstd_sum.count() / count;
#endif
auto avg_tot_encrypt=avg_encode+avg_encrypt+avg_serialize_zstd;
auto avg_tot_decrypt=avg_decode+avg_decrypt;

    cout<<"Average encrypt operation"<<avg_tot_encrypt<<endl;
    cout<<"Average encrypt operation"<<avg_tot_decrypt<<endl;

    cout << "Average encode: " << avg_encode << " microseconds" << endl;
    cout << "Average decode: " << avg_decode << " microseconds" << endl;
    cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
    cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
    cout << "Average add: " << avg_add << " microseconds" << endl;
    cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
    cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
    cout << "Average square: " << avg_square << " microseconds" << endl;
    if (context.using_keyswitching())
    {
        cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
        cout << "Average rescale: " << avg_rescale << " microseconds" << endl;
        cout << "Average rotate vector one step: " << avg_rotate_one_step << " microseconds" << endl;
        cout << "Average rotate vector random: " << avg_rotate_random << " microseconds" << endl;
        cout << "Average complex conjugate: " << avg_conjugate << " microseconds" << endl;
    }
    cout << "Average serialize ciphertext: " << avg_serialize << " microseconds" << endl;
#ifdef SEAL_USE_ZLIB
    cout << "Average compressed (ZLIB) serialize ciphertext: " << avg_serialize_zlib << " microseconds" << endl;
#endif
#ifdef SEAL_USE_ZSTD
    cout << "Average compressed (Zstandard) serialize ciphertext: " << avg_serialize_zstd << " microseconds" << endl;
#endif

    cout<<"Time operation: "<< time_operation <<" microseconds"<< endl;
    cout.flush();
}

void encryption_ckks_paillier(SEALContext context){
    //Init CKKS
   
    //Init Paillier

}
void paillier_example_sum(int num_addends) {
    int modulus_bits = 3072;
    paillier_pubkey_t *pubkey;
    paillier_prvkey_t *privkey;

    // Key Generation
    paillier_keygen(modulus_bits, &pubkey, &privkey, paillier_get_rand_devurandom);

    // Ciphertext Init
    paillier_ciphertext_t *sum_ciphertext = paillier_create_enc_zero();

    // Plaintext for verification
    mpz_t plaintext_sum;
    mpz_init(plaintext_sum);

    
    std::chrono::microseconds time_encode_sum(0), time_homomorphic_sum(0), time_decode_sum(0);
    size_t total_ciphertext_size = 0;

    // Cifrare e sommare gli addendi
    for (int i = 1; i <= num_addends; i++) {
        // Inizializza il valore dell'addendo in plaintext
        paillier_plaintext_t *plaintext_addend = paillier_plaintext_from_ui(i);
        mpz_add(plaintext_sum, plaintext_sum, plaintext_addend->m);  // Somma plaintext per verifica

        // Misura il tempo di crittografia
        auto time_start = std::chrono::high_resolution_clock::now();
        paillier_ciphertext_t *ciphertext_addend = paillier_enc(NULL, pubkey, plaintext_addend, paillier_get_rand_devurandom);
        auto time_end = std::chrono::high_resolution_clock::now();
        time_encode_sum += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

        // Calcola la dimensione del ciphertext
        size_t ciphertext_size = mpz_sizeinbase(ciphertext_addend->c, 2); // Dimensione in bit
        total_ciphertext_size += ciphertext_size;

        // Misura il tempo per l'operazione omomorfica
        time_start = std::chrono::high_resolution_clock::now();
        paillier_mul(pubkey, sum_ciphertext, sum_ciphertext, ciphertext_addend);
        time_end = std::chrono::high_resolution_clock::now();
        time_homomorphic_sum += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

        // Libera la memoria dell'addendo
        paillier_freeplaintext(plaintext_addend);
        paillier_freeciphertext(ciphertext_addend);
    }

    // decryption of the result
    auto time_start = std::chrono::high_resolution_clock::now();
    paillier_plaintext_t *decrypted_sum = paillier_dec(NULL, pubkey, privkey, sum_ciphertext);
    auto time_end = std::chrono::high_resolution_clock::now();
    time_decode_sum = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

    // Verificaition
    char* decrypted_sum_str = mpz_get_str(NULL, 10, decrypted_sum->m);
    char* plaintext_sum_str = mpz_get_str(NULL, 10, plaintext_sum);
    std::cout << "Decrypted sum of 1 to " << num_addends << ": " << decrypted_sum_str << std::endl;
    std::cout << "Expected sum of 1 to " << num_addends << ": " << plaintext_sum_str << std::endl;

    //Time
    auto avg_encode_time = time_encode_sum.count() / num_addends;
    auto avg_ciphertext_size = total_ciphertext_size / num_addends;
    std::cout << "Average encryption time: " << avg_encode_time << " microseconds" << std::endl;
    std::cout << "Total homomorphic addition time: " << time_homomorphic_sum.count() << " microseconds" << std::endl;
    std::cout << "Decryption time: " << time_decode_sum.count() << " microseconds" << std::endl;
    std::cout << "Average ciphertext size: " << avg_ciphertext_size << " bits, " << (avg_ciphertext_size + 7) / 8 << " bytes" << std::endl;

    // Export in csv
    std::ofstream file("paillier_performance_data.csv", std::ios::app);
    if (file.is_open()) {
        file << num_addends << "," 
             << avg_encode_time << "," 
             << time_homomorphic_sum.count() << "," 
             << time_decode_sum.count() << ","
             << avg_ciphertext_size << "\n";
        file.close();
        std::cout << "Data saved to paillier_performance_data.csv" << std::endl;
    } else {
        std::cerr << "Error opening file!" << std::endl;
    }

    // Memory freeing 
    free(decrypted_sum_str);
    free(plaintext_sum_str);
    mpz_clear(plaintext_sum);
    paillier_freepubkey(pubkey);
    paillier_freeprvkey(privkey);
    paillier_freeplaintext(decrypted_sum);
    paillier_freeciphertext(sum_ciphertext);
}


void generate_ckks_key_sizes(const std::string &filename) {
    // Apri il file per salvare le dimensioni delle chiavi
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return;
    }

    // Intestazione del file CSV
    outfile << "Polynomial Degree,Public Key (bytes),Secret Key (bytes),Relinearization Key (bytes),Galois Key (bytes)\n";


    // Partiamo dal grado 1024 e raddoppiamo fino a 32768
    for (size_t poly_degree = 1024; poly_degree <= 32768; poly_degree *= 2) {
        // Configura i parametri del contesto CKKS con SEAL
        seal::EncryptionParameters params(scheme_type::ckks);
        params.set_poly_modulus_degree(poly_degree);
        params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_degree)); 

        // Inizializza il contesto
//        auto context = SEALContext::Create(params);
        SEALContext context(params);
        RelinKeys relin_keys;
    	GaloisKeys gal_keys;
 	
    	PublicKey public_key;
   
        // Genera le chiavi
        KeyGenerator keygen(context);
         keygen.create_public_key(public_key);
      	 auto secret_key = keygen.secret_key();
  if (context.using_keyswitching()){
         keygen.create_relin_keys(relin_keys);
        keygen.create_galois_keys(gal_keys);
}
        // Scrivi le dimensioni delle chiavi nel file
        outfile << poly_degree << ","
                << public_key.save_size(seal::compr_mode_type::none) << ","
                << secret_key.save_size(seal::compr_mode_type::none) << ","
                << relin_keys.save_size(seal::compr_mode_type::none) << ","
                << gal_keys.save_size(seal::compr_mode_type::none) << "\n";

        std::cout << "Processed polynomial degree: " << poly_degree << std::endl;
    }

    // Chiudi il file
    outfile.close();
    std::cout << "Key sizes saved to " << filename << std::endl;
}


int main()
{
//Data preparation SECTION
for (int i=1; i<=2; i++){
    size_t packet_size = 20;
    generate_random_data(i);
  
    /*
    for (const auto& num : data_double) {
        std::cout << num << " ";  // Cast per stampare come interi
    }
    std::cout << std::endl;*/
    
//ENCRYTPION SECTION
//AES ENCRYPTION

    //aes_encryption(i);
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree1= 8192;

    parms.set_poly_modulus_degree(poly_modulus_degree1);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree1, {60,29,29,60}));

    //parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree1, seal::sec_level_type::tc128));
    //CKKS ENCRYPTION

    
  //  ckks_encryption(parms, i);



//EL Gamal Encryption

    //elGamal();

//Paillier Encryption

   // paillier();
  // paillier_example_sum(i);
}

//SCENARIO I - CKKS - PAILLIER
EncryptionParameters parmsScenario1(scheme_type::ckks);
size_t poly_modulus_degreeScenario1= 1024;
parmsScenario1.set_poly_modulus_degree(poly_modulus_degreeScenario1);
parmsScenario1.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degreeScenario1, seal::sec_level_type::tc128));

//encryption_ckks_paillier(parmsScenario1);
//SCENARIO II - CKKS Sum
//Scenario III - CKKS Variance

    EncryptionParameters parms2(scheme_type::ckks);
    size_t poly_modulus_degree2= 8192;
    parms2.set_poly_modulus_degree(poly_modulus_degree2);
    parms2.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree2, {60,29,29,60}));
    
    //parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 20, 20, 29}));
    //parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    ckks_variance(parms2);

    //generate_ckks_key_sizes("ckks_key_sizes.csv");
}