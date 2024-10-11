#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <openssl/des.h>
#include <chrono>
#include <mpi.h>
#include <cmath>
#include <omp.h>

// Función para agregar padding PKCS#7
std::vector<unsigned char> addPadding(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> padded = data;
    int padding = 8 - (data.size() % 8);
    if (padding == 0) padding = 8; // Añadir un bloque completo si ya está alineado
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

// Función para encriptar con DES
void encryptDES(unsigned long long key, unsigned char* data, int len) {
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }
    DES_set_odd_parity(&keyBlock);
    DES_key_schedule schedule;
    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        std::cerr << "Error: Clave DES inválida (paridad incorrecta)." << std::endl;
        return;
    }
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_ENCRYPT);
    }
}

// Función para desencriptar con DES
bool decryptDES(unsigned long long key, unsigned char* data, int len) {
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }
    DES_set_odd_parity(&keyBlock);
    DES_key_schedule schedule;
    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        return false;
    }
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_DECRYPT);
    }
    return true;
}

// Función para intentar una clave específica
bool tryKey(unsigned long long key, const unsigned char* cipher, int len, const std::string& phrase) {
    std::vector<unsigned char> temp(cipher, cipher + len);
    if (!decryptDES(key, temp.data(), len)) {
        return false;
    }
    std::vector<unsigned char> decryptedData = removePadding(temp);
    std::string decryptedText(decryptedData.begin(), decryptedData.end());
    return decryptedText.find(phrase) != std::string::npos;
}

int main(int argc, char* argv[]) {
    int provided;
    MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
    if (provided < MPI_THREAD_MULTIPLE) {
        std::cerr << "Error: MPI no soporta MPI_THREAD_MULTIPLE." << std::endl;
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

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

        // Calcular la longitud de la llave en bytes
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
        encryptDES(keyToEncrypt, cipher.data(), cipher.size());
        std::cout << "Cifrado terminado." << std::endl;

        // Mostrar el texto cifrado
        std::cout << "\nTexto cifrado: ";
        for (unsigned char c : cipher) {
            printf("%02X ", c);
        }
        std::cout << std::endl;

        // Pedir la frase para verificar el descifrado
        std::cout << "\nIntroduce la frase para verificar el descifrado: ";
        std::cin.ignore(); // Limpiar el buffer de entrada
        std::getline(std::cin, phrase);

        std::cout << "\nIniciando búsqueda de la llave correcta..." << std::endl;
    }

    // Broadcast de keyToEncrypt
    MPI_Bcast(&keyToEncrypt, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

    // Broadcast del tamaño del cipher
    int cipherSize = 0;
    if (rank == 0) {
        cipherSize = cipher.size();
    }
    MPI_Bcast(&cipherSize, 1, MPI_INT, 0, MPI_COMM_WORLD);

    // Resize el vector en los demás procesos
    if (rank != 0) {
        cipher.resize(cipherSize);
    }

    // Broadcast del contenido del cipher
    if (cipherSize > 0) {
        MPI_Bcast(cipher.data(), cipherSize, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    }

    // Broadcast del tamaño de la frase
    int phraseSize = 0;
    if (rank == 0) {
        phraseSize = phrase.size();
    }
    MPI_Bcast(&phraseSize, 1, MPI_INT, 0, MPI_COMM_WORLD);

    // Resize la frase en los demás procesos
    if (rank != 0) {
        phrase.resize(phraseSize);
    }

    // Broadcast del contenido de la frase
    if (phraseSize > 0) {
        // Asegurar que la cadena tiene suficiente espacio
        // En C++11 y posteriores, std::string's data is mutable si no está vacía
        if (phraseSize > 0) {
            MPI_Bcast(&phrase[0], phraseSize, MPI_CHAR, 0, MPI_COMM_WORLD);
        }
    }

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
    unsigned long long lowerLimit = 0;
    if (keyDigits == 1)
        lowerLimit = 0;
    else
        lowerLimit = pow(10, keyDigits - 1); // Mínimo número con keyDigits dígitos

    unsigned long long upperLimit = pow(10, keyDigits) - 1; // Máximo número con keyDigits dígitos

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

    unsigned long long foundKey = 0;

    // Sincronizar procesos antes de comenzar el temporizador
    MPI_Barrier(MPI_COMM_WORLD);
    auto start_time = std::chrono::high_resolution_clock::now();

    // Definir un tamaño de chunk
    unsigned long long chunkSize = 100000;
    unsigned long long currentStart = startKey;
    unsigned long long currentEnd = std::min(currentStart + chunkSize - 1, endKey);

    while (currentStart <= endKey && foundKey == 0) {
        #pragma omp parallel for schedule(dynamic)
        for (unsigned long long key = currentStart; key <= currentEnd; ++key) {
            if (foundKey != 0) continue;

            if (tryKey(key, cipher.data(), cipher.size(), phrase)) {
                #pragma omp critical
                {
                    if (foundKey == 0) {
                        foundKey = key;
                        std::cout << "\t➨ Thread " << omp_get_thread_num() << " en Rank " << rank << " encontró la llave: " << key << std::endl;
                    }
                }
            }

            // Opcional: Mostrar progreso cada cierto número de llaves
            if (key % 100000 == 0) {
                #pragma omp critical
                {
                    std::cout << "\t⇨ Rank " << rank << " está probando la llave: " << key << std::endl;
                }
            }
        }

        // Después de procesar el chunk, realizar una reducción colectiva para compartir el foundKey
        unsigned long long localFoundKey = foundKey;
        unsigned long long globalFoundKey = 0;
        MPI_Allreduce(&localFoundKey, &globalFoundKey, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);

        if (globalFoundKey != 0) {
            foundKey = globalFoundKey;
            break; // Salir del bucle principal si se encontró la llave
        }

        // Mover al siguiente chunk
        currentStart += chunkSize;
        currentEnd = std::min(currentStart + chunkSize - 1, endKey);
    }

    // Realizar una última reducción para asegurarse de que todos conocen el foundKey
    unsigned long long localFinalKey = foundKey;
    unsigned long long finalFoundKey = 0;
    MPI_Allreduce(&localFinalKey, &finalFoundKey, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);

    foundKey = finalFoundKey;

    // Medir el tiempo final
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end_time - start_time;

    // Mostrar el resultado en el proceso rank 0
    if (rank == 0) {
        if (foundKey != 0) {
            std::cout << "\n\nLlave encontrada: " << foundKey << std::endl;

            // Mostrar el texto descifrado
            std::vector<unsigned char> temp(cipher.begin(), cipher.end());
            if (decryptDES(foundKey, temp.data(), temp.size())) {
                std::vector<unsigned char> decryptedData = removePadding(temp);
                std::string decryptedText(decryptedData.begin(), decryptedData.end());
                std::cout << "Texto descifrado: " << decryptedText << std::endl;
            } else {
                std::cout << "Error al desencriptar con la llave encontrada." << std::endl;
            }
        } else {
            std::cout << "\nNo se encontró la llave." << std::endl;
        }
        std::cout << "Tiempo de ejecución: " << duration.count() << " segundos" << std::endl;
    }

    MPI_Finalize();
    return 0;
}

/**

    mpic++ -fopenmp -o op openMP.cpp -lssl -lcrypto
    mpirun -np 4 ./op
    
 */