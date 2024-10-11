// Archivo: des_linear_cryptanalysis_corrected.cpp

#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <openssl/des.h>
#include <chrono>
#include <mpi.h>
#include <cmath>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <algorithm>

// Definir la cantidad de pares de texto plano-cifrado a generar
#define NUM_PAIRS 1000000 // Puedes ajustar este valor según tus necesidades

// Estructura para almacenar pares de texto plano y texto cifrado con arreglos de tamaño fijo
struct PlainCipherPair {
    unsigned char plaintext[8];
    unsigned char ciphertext[8];
};

// Función para agregar padding PKCS#7
std::vector<unsigned char> addPadding(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> padded = data;
    int padding = 8 - (data.size() % 8);
    if (padding == 0) padding = 8;
    for (int i = 0; i < padding; ++i) {
        padded.push_back(static_cast<unsigned char>(padding));
    }
    return padded;
}

// Función para quitar padding PKCS#7
std::vector<unsigned char> removePadding(const std::vector<unsigned char>& data) {
    if (data.empty()) return data;
    int padding = data.back();
    if (padding < 1 || padding > 8) return data;
    return std::vector<unsigned char>(data.begin(), data.end() - padding);
}

// Función para convertir una clave numérica a DES_cblock
void numericKeyToDESKey(unsigned long long numericKey, DES_cblock& desKey) {
    // Convertir la clave numérica a una cadena con relleno de ceros a la izquierda hasta 13 dígitos
    char keyStr[14]; // 13 dígitos + null terminator
    snprintf(keyStr, sizeof(keyStr), "%013llu", numericKey);

    // Convertir la cadena a bytes, tomando dos dígitos por byte
    for (int i = 0; i < 8; ++i) {
        if (i * 2 + 1 < 13) {
            // Combinar dos dígitos por byte
            unsigned char high = keyStr[i * 2] - '0';
            unsigned char low = keyStr[i * 2 + 1] - '0';
            desKey[i] = (high << 4) | (low & 0x0F);
        }
        else if (i * 2 < 13) {
            // Último byte con un solo dígito
            unsigned char high = keyStr[i * 2] - '0';
            desKey[i] = (high << 4);
        }
        else {
            // Rellenar con ceros si excede
            desKey[i] = 0x00;
        }
    }

    // Ajustar los bits de paridad
    DES_set_odd_parity(&desKey);
}

// Función para cifrar con DES en modo ECB
void encrypt_DES(unsigned long long numericKey, unsigned char* data, int len) {
    DES_key_schedule ks;
    DES_cblock keyBlock;

    // Convertir la clave numérica a DES_cblock
    numericKeyToDESKey(numericKey, keyBlock);

    // Establecer la clave con paridad
    if (DES_set_key_checked(&keyBlock, &ks) != 0) {
        std::cerr << "Error al establecer la clave DES." << std::endl;
        exit(1);
    }

    // Cifrar en modo ECB
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &ks, DES_ENCRYPT);
    }
}

// Función para descifrar con DES en modo ECB
void decrypt_DES(unsigned long long numericKey, unsigned char* data, int len) {
    DES_key_schedule ks;
    DES_cblock keyBlock;

    // Convertir la clave numérica a DES_cblock
    numericKeyToDESKey(numericKey, keyBlock);

    // Establecer la clave con paridad
    if (DES_set_key_checked(&keyBlock, &ks) != 0) {
        std::cerr << "Error al establecer la clave DES." << std::endl;
        exit(1);
    }

    // Descifrar en modo ECB
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &ks, DES_DECRYPT);
    }
}

// Función para generar pares de texto plano-cifrado
std::vector<PlainCipherPair> generatePlainCipherPairs(unsigned long long key, unsigned long long numPairs) {
    std::vector<PlainCipherPair> pairs;
    pairs.reserve(numPairs);

    // Inicializar aleatoriedad con una semilla fija para reproducibilidad
    srand(42);

    for (unsigned long long i = 0; i < numPairs; ++i) {
        PlainCipherPair pair;

        // Generar un texto plano aleatorio de 8 bytes
        for (int j = 0; j < 8; ++j) {
            pair.plaintext[j] = rand() % 256;
        }

        // Copiar el texto plano para cifrar
        memcpy(pair.ciphertext, pair.plaintext, 8);
        encrypt_DES(key, pair.ciphertext, 8);

        // Almacenar el par
        pairs.push_back(pair);
    }

    return pairs;
}

// Función para realizar criptoanálisis lineal y calcular biases para subclaves
std::unordered_map<int, double> linearCryptanalysis(const std::vector<PlainCipherPair>& pairs, int num_subkey_bits) {
    // Esta es una implementación simplificada. En un ataque real, se necesitarían
    // las tablas de aproximación lineal específicas para DES y un análisis más detallado.

    // Contadores para cada subclave candidata
    int num_subkeys = 1 << num_subkey_bits;
    std::vector<int> counters(num_subkeys, 0);

    // Definir la aproximación lineal. Por simplicidad, consideraremos una
    // relación ficticia entre bits del texto plano, texto cifrado y la subclave.
    // En un ataque real, se utilizarían las LAT de DES.

    // Ejemplo de aproximación lineal:
    // p0 ^ p1 ^ k0 = c0 ^ c1
    // Donde:
    // - p0: bit 0 del primer byte del texto plano
    // - p1: bit 1 del primer byte del texto plano
    // - c0: bit 0 del primer byte del texto cifrado
    // - c1: bit 1 del primer byte del texto cifrado
    // - k0: bit 0 de la subclave candidata

    for (const auto& pair : pairs) {
        // Extraer bits específicos del texto plano y cifrado
        unsigned char p0 = (pair.plaintext[0] >> 0) & 0x01;
        unsigned char p1 = (pair.plaintext[0] >> 1) & 0x01;
        unsigned char c0 = (pair.ciphertext[0] >> 0) & 0x01;
        unsigned char c1 = (pair.ciphertext[0] >> 1) & 0x01;

        // Para cada subclave candidata, verificar la aproximación
        for (int k = 0; k < num_subkeys; ++k) {
            unsigned char k0 = (k >> 0) & 0x01;
            // Si num_subkey_bits > 1, considerar más bits aquí

            // Calcular la aproximación
            unsigned char approx = p0 ^ p1 ^ k0 ^ c0 ^ c1;

            if (approx == 0) {
                counters[k]++;
            }
        }
    }

    // Calcular biases
    std::unordered_map<int, double> biases;
    for (int k = 0; k < num_subkeys; ++k) {
        double bias = std::abs((static_cast<double>(counters[k]) / pairs.size()) - 0.5);
        biases[k] = bias;
    }

    return biases;
}

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    unsigned long long keyToEncrypt = 0;
    std::vector<unsigned char> cipher;
    std::string phrase;
    std::vector<unsigned char> plaintext;

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
        plaintext = std::vector<unsigned char>(text.begin(), text.end());
        plaintext = addPadding(plaintext);

        // Pedir al usuario la llave para cifrar y la frase de comparación
        std::cout << "Introduce la llave para cifrar el texto (entero de hasta 13 dígitos): ";
        std::cin >> keyToEncrypt;
        if (keyToEncrypt > 9999999999999ULL) {
            std::cerr << "Error: la llave excede 13 dígitos." << std::endl;
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        // Cifrar el texto usando la llave proporcionada
        std::cout << "\nIniciando cifrado..." << std::endl;
        cipher = plaintext; // Copiar el plaintext
        encrypt_DES(keyToEncrypt, cipher.data(), cipher.size());
        std::cout << "Cifrado terminado." << std::endl;

        // Mostrar el texto cifrado
        std::cout << "\nTexto cifrado: ";
        for (unsigned char c : cipher) {
            printf("%02X", c);
        }
        std::cout << std::endl;

        // Pedir la frase para verificar el descifrado
        std::cout << "Introduce la frase para verificar el descifrado: ";
        std::cin.ignore(); // Ignorar el salto de línea anterior
        std::getline(std::cin, phrase);
        std::cout << std::endl;
    }

    // Broadcast de keyToEncrypt, cipher, phrase y plaintext a todos los procesos
    MPI_Bcast(&keyToEncrypt, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

    int dataSize;
    if (rank == 0) {
        dataSize = cipher.size();
    }
    MPI_Bcast(&dataSize, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (rank != 0) {
        cipher.resize(dataSize);
        plaintext.resize(dataSize);
    }
    MPI_Bcast(cipher.data(), dataSize, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(plaintext.data(), dataSize, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    int phraseSize;
    if (rank == 0) {
        phraseSize = phrase.size();
    }
    MPI_Bcast(&phraseSize, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (rank != 0) {
        phrase.resize(phraseSize);
    }
    MPI_Bcast(&phrase[0], phraseSize, MPI_CHAR, 0, MPI_COMM_WORLD);

    // Proceso 0 genera todos los pares de texto plano-cifrado
    std::vector<PlainCipherPair> allPairs;
    if (rank == 0) {
        std::cout << "Generando " << NUM_PAIRS << " pares de texto plano-cifrado..." << std::endl;
        allPairs = generatePlainCipherPairs(keyToEncrypt, NUM_PAIRS);
        std::cout << "Generación de pares completada." << std::endl;
    }

    // Todos los procesos deben redimensionar allPairs para almacenar todos los pares
    if (rank != 0) {
        allPairs.resize(NUM_PAIRS);
    }

    // Broadcast de los pares a todos los procesos en bloques
    const unsigned long long PAIRS_PER_BROADCAST = 100000;
    unsigned long long total_broadcasts = (NUM_PAIRS + PAIRS_PER_BROADCAST - 1) / PAIRS_PER_BROADCAST;

    for (unsigned long long b = 0; b < total_broadcasts; ++b) {
        unsigned long long current_b = b;
        unsigned long long start = b * PAIRS_PER_BROADCAST;
        unsigned long long end = std::min(start + PAIRS_PER_BROADCAST, static_cast<unsigned long long>(NUM_PAIRS));
        unsigned long long current_size = end - start;

        // Broadcast del tamaño actual
        MPI_Bcast(&current_size, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

        // Preparar buffers
        std::vector<unsigned char> plaintext_buffer(current_size * 8);
        std::vector<unsigned char> ciphertext_buffer(current_size * 8);

        if (rank == 0) {
            for (unsigned long long i = start; i < end; ++i) {
                memcpy(&plaintext_buffer[(i - start) * 8], allPairs[i].plaintext, 8);
                memcpy(&ciphertext_buffer[(i - start) * 8], allPairs[i].ciphertext, 8);
            }
        }

        // Broadcast de los buffers
        MPI_Bcast(plaintext_buffer.data(), current_size * 8, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(ciphertext_buffer.data(), current_size * 8, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

        // Reconstruir los pares en cada proceso
        for (unsigned long long i = 0; i < current_size; ++i) {
            unsigned long long global_i = start + i;
            memcpy(allPairs[global_i].plaintext, &plaintext_buffer[i * 8], 8);
            memcpy(allPairs[global_i].ciphertext, &ciphertext_buffer[i * 8], 8);
        }
    }

    // Dividir los pares entre los procesos
    unsigned long long pairsPerProcess = NUM_PAIRS / size;
    unsigned long long startPair = rank * pairsPerProcess;
    unsigned long long endPair = (rank == size - 1) ? NUM_PAIRS : startPair + pairsPerProcess;

    std::vector<PlainCipherPair> myPairs(allPairs.begin() + startPair, allPairs.begin() + endPair);

    // Definir los bits de la subclave a atacar
    // Por simplicidad, atacaremos los primeros N bits de la subclave
    // En un ataque real, esto se basaría en la LAT y se dividiría adecuadamente
    const int NUM_SUBKEY_BITS = 8; // Ajusta según tus necesidades
    const int NUM_SUBKEYS = 1 << NUM_SUBKEY_BITS;

    // Realizar criptoanálisis lineal local
    auto localBiases = linearCryptanalysis(myPairs, NUM_SUBKEY_BITS);

    // Reducir las biases globales sumando las locales
    std::unordered_map<int, double> globalBiases;
    for (int k = 0; k < NUM_SUBKEYS; ++k) {
        double localBias = localBiases[k];
        double globalBias;
        MPI_Reduce(&localBias, &globalBias, 1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);
        if (rank == 0) {
            globalBiases[k] = globalBias;
        }
    }

    // En el proceso 0, determinar la subclave más probable
    if (rank == 0) {
        double maxBias = 0.0;
        int bestSubKey = -1;
        for (int k = 0; k < NUM_SUBKEYS; ++k) {
            // Bias total ya sumado por MPI_Reduce
            if (globalBiases[k] > maxBias) {
                maxBias = globalBiases[k];
                bestSubKey = k;
            }
            std::cout << "Subclave " << k << ": bias total = " << globalBiases[k] << std::endl;
        }

        std::cout << "\nLa subclave más probable es: " << bestSubKey << " con un bias total de " << maxBias << std::endl;

        // Dado que solo hemos atacado una parte de la clave, necesitamos inferir el resto
        // Aquí, se asume que la subclave atacada corresponde a los primeros NUM_SUBKEY_BITS bits de la clave DES
        // Esta es una simplificación y puede no ser precisa

        // Reconstruir parte de la clave DES
        unsigned long long inferred_subkey = bestSubKey;

        std::cout << "Iniciando búsqueda de la clave completa basada en la subclave inferida..." << std::endl;

        unsigned long long foundKey = 0;
        bool keyFound = false;

        // Definir el rango de claves numéricas a buscar
        unsigned long long MAX_KEY = 9999999999999ULL; // 13 dígitos
        unsigned long long keysPerProcess = MAX_KEY / size;
        unsigned long long startKeySearch = rank * keysPerProcess;
        unsigned long long endKeySearch = (rank == size - 1) ? MAX_KEY : startKeySearch + keysPerProcess - 1;

        for (unsigned long long k = startKeySearch; k <= endKeySearch && !keyFound; ++k) {
            // Convertir la clave numérica a DES key
            DES_cblock candidateKey;
            numericKeyToDESKey(k, candidateKey);

            // Extraer la subclave inferida de los bits atacados
            int extracted_subkey = 0;
            for (int b = 0; b < NUM_SUBKEY_BITS; ++b) {
                int byte = b / 8;
                int bit = b % 8;
                extracted_subkey <<= 1;
                extracted_subkey |= (candidateKey[0] >> (7 - bit)) & 0x01;
            }

            if (extracted_subkey == bestSubKey) {
                // Descifrar el texto cifrado original con la clave candidata
                std::vector<unsigned char> decrypted = cipher;
                decrypt_DES(k, decrypted.data(), decrypted.size());
                decrypted = removePadding(decrypted);
                std::string decryptedText(decrypted.begin(), decrypted.end());

                // Verificar si contiene la frase de verificación
                if (decryptedText.find(phrase) != std::string::npos) {
                    keyFound = true;
                    foundKey = k;
                    std::cout << "Proceso " << rank << " encontró la clave: " << foundKey << std::endl;
                }
            }
        }

        // Reducir para encontrar si algún proceso encontró la clave
        unsigned long long globalFoundKey = 0;
        MPI_Reduce(&foundKey, &globalFoundKey, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, 0, MPI_COMM_WORLD);

        // Verificar si se encontró la clave
        if (globalFoundKey != 0) {
            std::cout << "\nLlave encontrada: " << globalFoundKey << std::endl;

            // Descifrar el texto cifrado original con la clave encontrada
            std::vector<unsigned char> decrypted = cipher;
            decrypt_DES(globalFoundKey, decrypted.data(), decrypted.size());
            decrypted = removePadding(decrypted);
            std::string decryptedText(decrypted.begin(), decrypted.end());

            std::cout << "Texto descifrado: " << decryptedText << std::endl;
        }
        else {
            std::cout << "\nNo se pudo encontrar la clave completa basada en la subclave inferida." << std::endl;
        }
    }

    MPI_Finalize();
    return 0;
}
