#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <mpi.h>
#include <openssl/des.h>

// Función para encriptar datos con la clave dada
void encrypt(uint64_t key, std::vector<unsigned char>& data) {
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
    for (size_t i = 0; i < data.size(); i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data.data() + i), (DES_cblock*)(data.data() + i), &schedule, DES_ENCRYPT);
    }
}

// Función para desencriptar datos con la clave dada
bool decrypt(uint64_t key, std::vector<unsigned char>& data) {
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }
    DES_set_odd_parity(&keyBlock);
    DES_key_schedule schedule;
    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        // Clave débil o paridad inválida
        return false;
    }
    for (size_t i = 0; i < data.size(); i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data.data() + i), (DES_cblock*)(data.data() + i), &schedule, DES_DECRYPT);
    }
    return true;
}

// Función para intentar una clave y verificar si el texto descifrado contiene la frase buscada
bool tryKey(uint64_t key, const std::vector<unsigned char>& ciph, const std::string& phrase) {
    std::vector<unsigned char> temp = ciph;
    if (!decrypt(key, temp)) {
        return false; // Desencriptación fallida debido a clave débil u otro error
    }
    std::string decryptedText(temp.begin(), temp.end());
    return decryptedText.find(phrase) != std::string::npos;
}

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    // Clave conocida dentro del rango reducido
    uint64_t knownKey = 1234567; // Asegúrate de que esté dentro de totalKeys

    // Texto plano a cifrar
    std::string plaintext = "This is a test message.";

    // Frase a buscar en el texto descifrado
    std::string phrase = "test";

    // Convertir el texto plano a vector de unsigned char
    std::vector<unsigned char> cipher(plaintext.begin(), plaintext.end());

    // Agregar padding si es necesario para que la longitud sea múltiplo de 8
    while (cipher.size() % 8 != 0) {
        cipher.push_back(' ');
    }

    // Cifrar el texto plano con la clave conocida (solo lo hace un proceso)
    if (rank == 0) {
        encrypt(knownKey, cipher);
    }

    // Broadcast del texto cifrado a todos los procesos
    int cipherSize = cipher.size();
    MPI_Bcast(&cipherSize, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (rank != 0) {
        cipher.resize(cipherSize);
    }
    MPI_Bcast(cipher.data(), cipherSize, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    // Límite superior de claves (por ejemplo, 10 millones)
    uint64_t totalKeys = 10000000ULL; // Asegúrate de que knownKey < totalKeys

    // Dividir el espacio de claves entre los procesos
    uint64_t keysPerProcess = totalKeys / size;
    uint64_t remainder = totalKeys % size;

    uint64_t startKey, endKey;
    if (rank < remainder) {
        startKey = rank * (keysPerProcess + 1);
        endKey = startKey + keysPerProcess;
    } else {
        startKey = rank * keysPerProcess + remainder;
        endKey = startKey + keysPerProcess - 1;
    }

    uint64_t foundKey = 0;
    bool keyFound = false;
    MPI_Request foundKeyRequest;
    int flag = 0;

    // Iniciar temporizador
    double startTime = MPI_Wtime();

    // Iniciar recepción no bloqueante para obtener la clave encontrada por otros procesos
    MPI_Irecv(&foundKey, 1, MPI_UINT64_T, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &foundKeyRequest);

    // Iniciar la búsqueda de la clave
    for (uint64_t key = startKey; key <= endKey; ++key) {
        // Verificar si otro proceso ha encontrado la clave
        MPI_Test(&foundKeyRequest, &flag, MPI_STATUS_IGNORE);
        if (flag && foundKey != 0) {
            // La clave ha sido encontrada por otro proceso
            keyFound = true;
            break;
        }

        // Intentar la clave actual
        if (tryKey(key, cipher, phrase)) {
            foundKey = key;
            keyFound = true;
            // Enviar la clave encontrada a todos los otros procesos
            for (int i = 0; i < size; ++i) {
                if (i != rank) {
                    MPI_Send(&foundKey, 1, MPI_UINT64_T, i, 0, MPI_COMM_WORLD);
                }
            }
            break;
        }

        // Mostrar progreso cada cierto número de claves
        if (key % 1000000 == 0) {
            std::cout << "Proceso " << rank << " está en la clave: " << key << std::endl;
        }
    }

    // Si la clave no fue encontrada por este proceso ni recibida, esperar por ella
    if (!keyFound) {
        MPI_Wait(&foundKeyRequest, MPI_STATUS_IGNORE);
        keyFound = foundKey != 0;
    }

    // Finalizar temporizador
    double endTime = MPI_Wtime();

    // Proceso 0 muestra el resultado
    if (rank == 0) {
        if (foundKey != 0) {
            // Desencriptar el texto cifrado con la clave encontrada
            std::vector<unsigned char> decryptedData = cipher;
            decrypt(foundKey, decryptedData);
            std::string decryptedText(decryptedData.begin(), decryptedData.end());

            std::cout << "\nClave encontrada: " << foundKey << std::endl;
            std::cout << "Texto descifrado: " << decryptedText << std::endl;
            std::cout << "Tiempo de ejecución: " << (endTime - startTime) << " segundos" << std::endl;
        } else {
            std::cout << "No se encontró la clave." << std::endl;
        }
    }

    MPI_Finalize();
    return 0;
}
