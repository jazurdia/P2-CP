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


        // Calcular la longitud de la llave en bytes (código corregido)
        unsigned int keyByteLength = 0;
        unsigned long long tempKeyLength = keyToEncrypt;
        if (tempKeyLength == 0) {
            keyByteLength = 1; // Si la llave es 0, ocupa al menos 1 byte
        } else {
            while (tempKeyLength > 0) {
                keyByteLength++;
                tempKeyLength >>= 8; // Desplazar 8 bits (1 byte)
            }
        }

        std::cout << "La longitud de la llave es: " << keyByteLength << " bytes" << std::endl;

        // Cifrar el texto usando la llave proporcionada
        std::cout << "\nIniciando cifrado..." << std::endl;
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

        std::cout << "\nIniciando búsqueda de la llave correcta..." << std::endl;


    }

    // Sincronizar procesos y asegurar que otros esperen hasta que el rank 0 esté listo
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

    // Ahora todos los procesos tienen keyToEncrypt, cipher y phrase

    // Determinar la longitud en dígitos de la llave
    unsigned int keyDigits = 0;
    unsigned long long tempKey = keyToEncrypt;
    while (tempKey > 0) {
        tempKey /= 10;
        keyDigits++;
    }
    if (keyDigits == 0) {
        keyDigits = 1; // Si la llave es 0, tiene al menos un dígito
    }

    // Calcular el rango de llaves numéricas a probar
    unsigned long long lowerLimit = pow(10, keyDigits - 1); // Mínimo número con keyDigits dígitos
    unsigned long long upperLimit = pow(10, keyDigits) - 1; // Máximo número con keyDigits dígitos

    // Dividir el rango entre los procesos
    unsigned long long totalKeys = upperLimit - lowerLimit + 1;
    unsigned long long keysPerProcess = totalKeys / size;
    unsigned long long remainder = totalKeys % size;

    unsigned long long startKey, endKey;
    if (rank < remainder) {
        startKey = lowerLimit + rank * (keysPerProcess + 1);
        endKey = startKey + keysPerProcess;
    } else {
        startKey = lowerLimit + rank * keysPerProcess + remainder;
        endKey = startKey + keysPerProcess - 1;
    }

    unsigned long long found = 0;
    bool keyFound = false;
    bool keyFoundGlobal = false;

    // Medir el tiempo de ejecución
    auto start_time = std::chrono::high_resolution_clock::now();

    for (unsigned long long key = startKey; key <= endKey && !keyFoundGlobal; ++key) {
        // Verificar si el número tiene la cantidad correcta de dígitos
        if (std::to_string(key).length() != keyDigits) {
            continue; // Saltar números con menos dígitos
        }

        if (key % 1000000 == 0) {
            std::cout << "\t⇨ Rank " << rank << " está probando la llave: " << key << std::endl;
        }

        if (tryKey(key, cipher.data(), cipher.size(), phrase)) {
            std::cout << "\t➨ Rank " << rank << " encontró la llave: " << key << std::endl;

            found = key;
            keyFound = true;
        }

        // Actualizar keyFoundGlobal
        int localFlag = keyFound ? 1 : 0;
        int globalFlag = 0;
        MPI_Allreduce(&localFlag, &globalFlag, 1, MPI_INT, MPI_LOR, MPI_COMM_WORLD);
        keyFoundGlobal = globalFlag;

        if (keyFoundGlobal) {

            break; // Salir del bucle si la llave ha sido encontrada
        }
    }

    // Recopilar resultados de cada proceso
    unsigned long long globalFound = 0;
    MPI_Allreduce(&found, &globalFound, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);

    // Medir el tiempo final
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end_time - start_time;

    // Mostrar el resultado
    if (rank == 0) {
        if (globalFound != 0) {
            std::cout << "\n\nLlave encontrada: " << globalFound << std::endl;

            // mostar el texto descifrado. 
            std::vector<unsigned char> temp(cipher.begin(), cipher.end());
            decrypt(globalFound, temp.data(), temp.size());
            std::vector<unsigned char> decryptedData = removePadding(temp);
            std::string decryptedText(decryptedData.begin(), decryptedData.end());
            std::cout << "Texto descifrado: " << decryptedText << std::endl;

        } else {
            std::cout << "No se encontró la llave." << std::endl;
        }
        std::cout << "Tiempo de ejecución: " << duration.count() << " segundos" << std::endl;
    }

    MPI_Finalize();
    return 0;
}
