#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <openssl/des.h>
#include <chrono>
#include <mpi.h>
#include <cmath> // Para pow

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

void encrypt(unsigned long long key, unsigned char* data, int len) {
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }
    DES_set_odd_parity(&keyBlock);
    DES_key_schedule schedule;
    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        std::cerr << "Error setting key." << std::endl;
        return;
    }
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_ENCRYPT);
    }
}

bool decrypt(unsigned long long key, unsigned char* data, int len) {
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }
    DES_set_odd_parity(&keyBlock);
    DES_key_schedule schedule;
    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        // Weak key or invalid parity
        return false;
    }
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_DECRYPT);
    }
    return true;
}

bool tryKey(unsigned long long key, const unsigned char* ciph, int len, const std::string& phrase) {
    std::vector<unsigned char> temp(ciph, ciph + len);
    if (!decrypt(key, temp.data(), len)) {
        return false; // Decrypt failed due to weak key or other error
    }
    std::vector<unsigned char> decryptedData = removePadding(temp);
    std::string decryptedText(decryptedData.begin(), decryptedData.end());
    return decryptedText.find(phrase) != std::string::npos;
}

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    unsigned long long keyToEncrypt = 0;
    std::vector<unsigned char> cipher;
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

        // Convertir el texto a cifrar a un arreglo de unsigned char con padding
        cipher = std::vector<unsigned char>(text.begin(), text.end());
        cipher = addPadding(cipher);

        // Pedir al usuario la llave para cifrar y la frase de comparación
        std::cout << "Introduce la llave para cifrar el texto (entero): ";
        std::cin >> keyToEncrypt;

        // Cifrar el texto usando la llave proporcionada
        encrypt(keyToEncrypt, cipher.data(), cipher.size());
        std::cout << "Cifrado terminado." << std::endl;

        // Mostrar el texto cifrado
        std::cout << "\nTexto cifrado: ";
        for (unsigned char c : cipher) {
            printf("%02X", c);
        }

        std::cout << "\nIntroduce la frase para verificar el descifrado: ";
        std::cin.ignore();
        std::getline(std::cin, phrase);

        std::cout << std::endl;
    }

    // Broadcast de los datos necesarios para todos los procesos
    MPI_Bcast(&keyToEncrypt, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

    int cipherSize;
    if (rank == 0) {
        cipherSize = cipher.size();
    }
    MPI_Bcast(&cipherSize, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (rank != 0) {
        cipher.resize(cipherSize);
    }
    if (cipherSize > 0) {
        MPI_Bcast(cipher.data(), cipherSize, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    }

    int phraseSize;
    if (rank == 0) {
        phraseSize = phrase.size();
    }
    MPI_Bcast(&phraseSize, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (rank != 0) {
        phrase.resize(phraseSize);
    }
    if (phraseSize > 0) {
        MPI_Bcast(&phrase[0], phraseSize, MPI_CHAR, 0, MPI_COMM_WORLD);
    }

    // Dividir el trabajo (Master-Slave)
    unsigned long long lowerLimit = 0;
    unsigned long long upperLimit = pow(2, 56) - 1; // Rango de llaves DES de 56 bits

    unsigned long long totalKeys = upperLimit - lowerLimit + 1;
    unsigned long long keysPerProcess = totalKeys / (size - 1); // Esclavos ejecutarán el trabajo

    unsigned long long foundKey = 0;
    bool keyFound = false;

    int globalFlag = 0; // Variable global que indica si se encontró una llave

    if (rank == 0) {
        // Proceso maestro
        for (int i = 1; i < size; ++i) {
            unsigned long long recvKey;
            MPI_Recv(&recvKey, 1, MPI_UNSIGNED_LONG_LONG, i, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            if (recvKey != 0) {
                foundKey = recvKey;
                keyFound = true;
            }
        }

        if (keyFound) {
            std::cout << "Llave encontrada: " << foundKey << std::endl;

            // Descifrar el texto usando la llave encontrada
            std::vector<unsigned char> temp(cipher.begin(), cipher.end());
            decrypt(foundKey, temp.data(), temp.size());
            std::vector<unsigned char> decryptedData = removePadding(temp);
            std::string decryptedText(decryptedData.begin(), decryptedData.end());
            std::cout << "Texto descifrado: " << decryptedText << std::endl;

            // Indicar a los esclavos que la llave ha sido encontrada
            globalFlag = 1;
        }

        // Informar a todos los procesos que se encontró una llave
        MPI_Bcast(&globalFlag, 1, MPI_INT, 0, MPI_COMM_WORLD);

    } else {
        // Procesos esclavos
        unsigned long long startKey = lowerLimit + (rank - 1) * keysPerProcess;
        unsigned long long endKey = (rank == size - 1) ? upperLimit : startKey + keysPerProcess - 1;

        for (unsigned long long key = startKey; key <= endKey; ++key) {
            // Revisar si la llave ya fue encontrada por otro proceso
            MPI_Bcast(&globalFlag, 1, MPI_INT, 0, MPI_COMM_WORLD);
            if (globalFlag == 1) {
                std::cout << "[Rank " << rank << "] Llave ya encontrada, deteniendo búsqueda." << std::endl;
                break; // Detener la búsqueda si ya se encontró la llave
            }

            if (tryKey(key, cipher.data(), cipher.size(), phrase)) {
                foundKey = key;
                std::cout << "[Rank " << rank << "] Llave encontrada: " << foundKey << std::endl;
                MPI_Send(&foundKey, 1, MPI_UNSIGNED_LONG_LONG, 0, 0, MPI_COMM_WORLD);
                break;
            }
        }
    }

    MPI_Finalize();
    return 0;
}
