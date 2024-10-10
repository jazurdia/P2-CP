#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <openssl/des.h>
#include <chrono>
#include <mpi.h>
#include <cmath>
#include <cstring>

// Funciones de cifrado y descifrado simples (DES)
void encrypt(unsigned long long key, unsigned char* data, int len) {
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }
    DES_key_schedule schedule;
    DES_set_key_unchecked(&keyBlock, &schedule);
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((const_DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_ENCRYPT);
    }
}

void decrypt(unsigned long long key, unsigned char* data, int len) {
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }
    DES_key_schedule schedule;
    DES_set_key_unchecked(&keyBlock, &schedule);
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((const_DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_DECRYPT);
    }
}

// Funciones para Double DES
void double_encrypt(unsigned long long key1, unsigned long long key2, unsigned char* data, int len) {
    encrypt(key1, data, len);
    encrypt(key2, data, len);
}

void double_decrypt(unsigned long long key1, unsigned long long key2, unsigned char* data, int len) {
    decrypt(key2, data, len);
    decrypt(key1, data, len);
}

// Función para agregar padding PKCS#7
std::vector<unsigned char> addPadding(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> padded = data;
    int padding = 8 - (data.size() % 8);
    for (int i = 0; i < padding; ++i) {
        padded.push_back(static_cast<unsigned char>(padding));
    }
    return padded;
}

// Función para quitar padding PKCS#7
std::vector<unsigned char> removePadding(const std::vector<unsigned char>& data) {
    if (data.empty()) return data;
    int padding = data.back();
    if (padding < 1 || padding > 8) return data; // Padding inválido
    return std::vector<unsigned char>(data.begin(), data.end() - padding);
}

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);
    int rank, size;

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    unsigned long long key1 = 0, key2 = 0;
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> ciphertext;
    std::string phrase;

    if (rank == 0) {
        // Leer el texto desde el archivo input.txt
        std::ifstream inputFile("input.txt");
        if (!inputFile) {
            std::cerr << "Error: no se pudo abrir el archivo input.txt" << std::endl;
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        std::string text((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
        inputFile.close();
        if (text.empty()) {
            std::cerr << "El archivo input.txt está vacío." << std::endl;
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        plaintext = std::vector<unsigned char>(text.begin(), text.end());
        plaintext = addPadding(plaintext);

        // Pedir al usuario las llaves para cifrar y la frase de comparación
        std::cout << "Introduce la primera llave para cifrar el texto (entero): ";
        std::cin >> key1;

        std::cout << "Introduce la segunda llave para cifrar el texto (entero): ";
        std::cin >> key2;

        // Cifrar el texto usando Double DES
        ciphertext = plaintext; // Copiar el texto plano
        std::cout << "\nIniciando cifrado Double DES..." << std::endl;
        double_encrypt(key1, key2, ciphertext.data(), ciphertext.size());
        std::cout << "Cifrado terminado." << std::endl;

        // Mostrar el texto cifrado
        std::cout << "\nTexto cifrado: ";
        for (unsigned char c : ciphertext) {
            printf("%02X", c);
        }

        std::cout << "\nIntroduce la frase para verificar el descifrado: ";
        std::cin.ignore();
        std::getline(std::cin, phrase);

        std::cout << "\nIniciando ataque Meet-in-the-Middle..." << std::endl;
    }

    // Compartir datos con todos los procesos
    // Enviar y recibir tamaños primero
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

    // Compartir las claves originales (solo para información, no se utilizan en el ataque)
    MPI_Bcast(&key1, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);
    MPI_Bcast(&key2, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

    // Definir el espacio de claves (ejemplo: claves de 24 bits)
    unsigned long long maxKey = (1ULL << 24); // 24 bits

    // Dividir el espacio de claves entre los procesos
    unsigned long long keysPerProcess = maxKey / size;
    unsigned long long startKey = rank * keysPerProcess;
    unsigned long long endKey = (rank == size - 1) ? maxKey : startKey + keysPerProcess;

    // Fase 1: Cada proceso genera su parte de la tabla E(K1, P)
    std::unordered_map<std::string, unsigned long long> table;

    // Medir el tiempo de ejecución
    auto start_time = std::chrono::high_resolution_clock::now();

    for (unsigned long long k = startKey; k < endKey; ++k) {
        std::vector<unsigned char> temp = plaintext;
        encrypt(k, temp.data(), temp.size());
        std::string hash(reinterpret_cast<char*>(temp.data()), temp.size());
        table[hash] = k;
    }

    // Reunir todas las tablas en un solo proceso (por simplicidad, usaremos el proceso 0)
    // Esto puede requerir mucha memoria; en entornos reales, se deben utilizar técnicas de reducción de memoria.
    int tableSize = table.size();
    std::vector<int> tableSizes(size);

    MPI_Gather(&tableSize, 1, MPI_INT, tableSizes.data(), 1, MPI_INT, 0, MPI_COMM_WORLD);

    // Recolectar las tablas en el proceso 0
    std::unordered_map<std::string, unsigned long long> globalTable;

    if (rank == 0) {
        globalTable = table;
        for (int i = 1; i < size; ++i) {
            int recvSize = tableSizes[i];
            for (int j = 0; j < recvSize; ++j) {
                unsigned long long key;
                int dataSize = ciphertextSize;
                std::vector<unsigned char> data(dataSize);
                MPI_Recv(&key, 1, MPI_UNSIGNED_LONG_LONG, i, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                MPI_Recv(data.data(), dataSize, MPI_UNSIGNED_CHAR, i, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                std::string hash(reinterpret_cast<char*>(data.data()), dataSize);
                globalTable[hash] = key;
            }
        }
    } else {
        // Enviar tabla al proceso 0
        for (const auto& pair : table) {
            unsigned long long key = pair.second;
            std::vector<unsigned char> data(pair.first.begin(), pair.first.end());
            MPI_Send(&key, 1, MPI_UNSIGNED_LONG_LONG, 0, 0, MPI_COMM_WORLD);
            MPI_Send(data.data(), data.size(), MPI_UNSIGNED_CHAR, 0, 0, MPI_COMM_WORLD);
        }
    }

    // Fase 2: Proceso 0 realiza la búsqueda de coincidencias
    if (rank == 0) {
        unsigned long long foundK1 = 0, foundK2 = 0;
        bool found = false;

        for (unsigned long long k = 0; k < maxKey; ++k) {
            std::vector<unsigned char> temp = ciphertext;
            decrypt(k, temp.data(), temp.size());
            std::string hash(reinterpret_cast<char*>(temp.data()), temp.size());

            if (globalTable.find(hash) != globalTable.end()) {
                foundK1 = globalTable[hash];
                foundK2 = k;
                found = true;
                break;
            }
        }

        // Medir el tiempo final
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end_time - start_time;

        if (found) {
            std::cout << "\nLlaves encontradas:" << std::endl;
            std::cout << "K1: " << foundK1 << std::endl;
            std::cout << "K2: " << foundK2 << std::endl;

            // Descifrar el texto usando las llaves encontradas
            std::vector<unsigned char> decrypted = ciphertext;
            double_decrypt(foundK1, foundK2, decrypted.data(), decrypted.size());
            decrypted = removePadding(decrypted);
            std::string decryptedText(decrypted.begin(), decrypted.end());

            std::cout << "Texto descifrado: " << decryptedText << std::endl;
            std::cout << "Tiempo de ejecución: " << duration.count() << " segundos" << std::endl;
        } else {
            std::cout << "No se encontraron las llaves." << std::endl;
        }
    }

    MPI_Finalize();
    return 0;
}

/**

mpic++ -o mim mim.cpp -lssl -lcrypto
mpirun -np 4 ./mim

 */