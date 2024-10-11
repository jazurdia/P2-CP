#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <openssl/des.h>
#include <chrono>
#include <mpi.h>
#include <cmath>
#include <cstring>

// Encrypt with key part K1
void encrypt_part(unsigned long long key_part, unsigned char* data, int len) {
    DES_cblock keyBlock = {0};
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key_part >> (8 * (7 - i))) & 0xFF;
    }
    DES_key_schedule schedule;
    DES_set_key_unchecked(&keyBlock, &schedule);
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((const_DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_ENCRYPT);
    }
}

// Decrypt with key part K2
void decrypt_part(unsigned long long key_part, unsigned char* data, int len) {
    DES_cblock keyBlock = {0};
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key_part >> (8 * (7 - i))) & 0xFF;
    }
    DES_key_schedule schedule;
    DES_set_key_unchecked(&keyBlock, &schedule);
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((const_DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_DECRYPT);
    }
}

// Function to add PKCS#7 padding
std::vector<unsigned char> addPadding(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> padded = data;
    int padding = 8 - (data.size() % 8);
    for (int i = 0; i < padding; ++i) {
        padded.push_back(static_cast<unsigned char>(padding));
    }
    return padded;
}

// Function to remove PKCS#7 padding
std::vector<unsigned char> removePadding(const std::vector<unsigned char>& data) {
    if (data.empty()) return data;
    int padding = data.back();
    if (padding < 1 || padding > 8) return data; // Invalid padding
    return std::vector<unsigned char>(data.begin(), data.end() - padding);
}

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);
    int rank, size;

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    unsigned long long key = 0;
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> ciphertext;
    std::string phrase;

    if (rank == 0) {
        // Read the text from input.txt
        std::ifstream inputFile("input.txt");
        if (!inputFile) {
            std::cerr << "Error: Unable to open input.txt" << std::endl;
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        std::string text((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
        inputFile.close();
        if (text.empty()) {
            std::cerr << "input.txt is empty." << std::endl;
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        plaintext = std::vector<unsigned char>(text.begin(), text.end());
        plaintext = addPadding(plaintext);

        // Ask the user for the key to encrypt and the phrase to verify
        std::cout << "Enter the key to encrypt the text (integer): ";
        std::cin >> key;

        // Encrypt the text using Double DES (E(K, E(K, P)))
        ciphertext = plaintext; // Copy plaintext
        std::cout << "\nStarting Double DES encryption..." << std::endl;
        encrypt_part(key, ciphertext.data(), ciphertext.size());
        encrypt_part(key, ciphertext.data(), ciphertext.size());
        std::cout << "Encryption completed." << std::endl;

        // Display the encrypted text
        std::cout << "\nEncrypted text: ";
        for (unsigned char c : ciphertext) {
            printf("%02X", c);
        }

        std::cout << "\nEnter the phrase to verify decryption: ";
        std::cin.ignore();
        std::getline(std::cin, phrase);

        std::cout << "\nStarting meet-in-the-middle attack on DES..." << std::endl;
    }

    // Share data with all processes
    // Send and receive sizes first
    int plaintextSize = 0, ciphertextSize = 0, phraseSize = 0;

    if (rank == 0) {
        plaintextSize = plaintext.size();
        ciphertextSize = ciphertext.size();
        phraseSize = phrase.size();
    }

    MPI_Bcast(&plaintextSize, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&ciphertextSize, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&phraseSize, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (rank != 0) {
        plaintext.resize(plaintextSize);
        ciphertext.resize(ciphertextSize);
        phrase.resize(phraseSize);
    }

    if (plaintextSize > 0)
        MPI_Bcast(plaintext.data(), plaintextSize, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    if (ciphertextSize > 0)
        MPI_Bcast(ciphertext.data(), ciphertextSize, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    if (phraseSize > 0)
        MPI_Bcast(&phrase[0], phraseSize, MPI_CHAR, 0, MPI_COMM_WORLD);

    // Share the original key (for information, not used in the attack)
    MPI_Bcast(&key, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

    // Define the key space (e.g., 24-bit keys for each half)
    unsigned long long maxKeyPart = (1ULL << 24); // 16 bits for demonstration

    // Divide the key space among processes
    unsigned long long keysPerProcess = maxKeyPart / size;
    unsigned long long startKey = rank * keysPerProcess;
    unsigned long long endKey = (rank == size - 1) ? maxKeyPart : startKey + keysPerProcess;

    // Each process computes E(K, P) for its range of K
    std::unordered_map<std::string, unsigned long long> forwardTable;

    // Start measuring execution time
    auto start_time = std::chrono::high_resolution_clock::now();

    for (unsigned long long k = startKey; k < endKey; ++k) {
        std::vector<unsigned char> temp = plaintext;
        encrypt_part(k, temp.data(), temp.size());
        std::string intermediate(reinterpret_cast<char*>(temp.data()), temp.size());
        forwardTable[intermediate] = k;
    }

    // Gather all forward tables to the master process
    int tableSize = forwardTable.size();
    std::vector<int> tableSizes(size);

    MPI_Gather(&tableSize, 1, MPI_INT, tableSizes.data(), 1, MPI_INT, 0, MPI_COMM_WORLD);

    std::unordered_map<std::string, unsigned long long> globalForwardTable;

    if (rank == 0) {
        // Merge the tables from all processes
        globalForwardTable = forwardTable;
        for (int i = 1; i < size; ++i) {
            int recvSize = tableSizes[i];
            for (int j = 0; j < recvSize; ++j) {
                unsigned long long keyPart;
                int dataSize = plaintextSize; // Should be plaintextSize
                std::vector<unsigned char> data(dataSize);
                MPI_Recv(&keyPart, 1, MPI_UNSIGNED_LONG_LONG, i, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                MPI_Recv(data.data(), dataSize, MPI_UNSIGNED_CHAR, i, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                std::string intermediate(reinterpret_cast<char*>(data.data()), dataSize);
                globalForwardTable[intermediate] = keyPart;
            }
        }
    } else {
        // Send the table to the master process
        for (const auto& pair : forwardTable) {
            unsigned long long keyPart = pair.second;
            std::vector<unsigned char> data(pair.first.begin(), pair.first.end());
            MPI_Send(&keyPart, 1, MPI_UNSIGNED_LONG_LONG, 0, 0, MPI_COMM_WORLD);
            MPI_Send(data.data(), data.size(), MPI_UNSIGNED_CHAR, 0, 0, MPI_COMM_WORLD);
        }
    }

    // Master process performs the meet-in-the-middle search
    if (rank == 0) {
        bool found = false;
        unsigned long long foundKey = 0;

        // For all possible K, compute D(K, C) and look for matches
        for (unsigned long long k = 0; k < maxKeyPart; ++k) {
            std::vector<unsigned char> temp = ciphertext;
            decrypt_part(k, temp.data(), temp.size());
            std::string intermediate(reinterpret_cast<char*>(temp.data()), temp.size());

            if (globalForwardTable.find(intermediate) != globalForwardTable.end()) {
                foundKey = globalForwardTable[intermediate];
                found = true;
                break;
            }
        }

        // Stop measuring execution time
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end_time - start_time;

        if (found) {
            std::cout << "\nKey found: " << foundKey << std::endl;

            // Decrypt the text using the found key
            std::vector<unsigned char> decrypted = ciphertext;
            decrypt_part(foundKey, decrypted.data(), decrypted.size());
            decrypt_part(foundKey, decrypted.data(), decrypted.size());
            decrypted = removePadding(decrypted);
            std::string decryptedText(decrypted.begin(), decrypted.end());

            std::cout << "Decrypted text: " << decryptedText << std::endl;
            std::cout << "Execution time: " << duration.count() << " seconds" << std::endl;
        } else {
            std::cout << "Key not found." << std::endl;
        }
    }

    MPI_Finalize();
    return 0;
}

/**

Compile and run the program:

mpic++ -o mim2 mim2.cpp -lssl -lcrypto
mpirun -np 4 ./mim2

 */