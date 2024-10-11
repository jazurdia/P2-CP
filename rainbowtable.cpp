#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <chrono>
#include <mpi.h>
#include <sstream>
#include <cstring>
#include <numeric>

// Función hash (simple) para la llave
std::string hashFunction(const unsigned char* data, int len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << (int)hash[i];
    }
    return ss.str();
}

// Reducción de un hash a una nueva llave (para Rainbow Tables)
unsigned long long reduceHash(const std::string& hash, int iteration) {
    unsigned long long key = 0;
    for (int i = 0; i < 8; ++i) {
        key = (key << 4) | (hash[i] & 0xF); // Usa los primeros 8 hexadecimales
    }
    return key ^ iteration; // Incluir la iteración para diversificar
}

// Modificar convertKey para soportar claves de cualquier longitud
void convertKey(const std::string& userKey, DES_cblock& keyBlock) {
    // Generar un hash MD5 de la clave de usuario
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(userKey.c_str()), userKey.size(), hash);
    
    // Usar los primeros 8 bytes del hash como clave
    memcpy(keyBlock, hash, 8);
    DES_set_odd_parity(&keyBlock); // Ajustar la paridad
}

// Función para cifrar con DES
void encrypt(const std::string& userKey, unsigned char* data, int len) {
    DES_cblock keyBlock;
    convertKey(userKey, keyBlock); // Convertir la clave de usuario

    DES_key_schedule schedule;
    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        std::cerr << "Error setting key." << std::endl;
        return;
    }

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_ENCRYPT);
    }
}

// Función para descifrar con DES
bool decrypt(const std::string& userKey, unsigned char* data, int len) {
    DES_cblock keyBlock;
    convertKey(userKey, keyBlock); // Convertir la clave de usuario

    DES_key_schedule schedule;
    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        return false;
    }

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_DECRYPT);
    }
    return true;
}

// Generar una tabla rainbow para un rango de llaves
// Generar una tabla rainbow para un rango de llaves
void generateRainbowTable(unsigned long long lowerLimit, unsigned long long upperLimit, int chainLength, std::unordered_map<std::string, unsigned long long>& rainbowTable) {
    std::string knownText = "proyecto"; // Texto conocido para cifrar y generar hashes
    unsigned char data[8];
    memcpy(data, knownText.c_str(), 8);

    std::cout << "Iniciando generación de la tabla rainbow..." << std::endl;
    std::cout << "Rango de llaves: " << lowerLimit << " a " << upperLimit << std::endl;
    std::cout << "Longitud de la cadena: " << chainLength << std::endl;

    for (unsigned long long key = lowerLimit; key <= upperLimit; ++key) {
        unsigned long long currentKey = key;
        std::string hash;

        std::cout << "Procesando llave: " << key << std::endl;

        for (int i = 0; i < chainLength; ++i) {
            std::cout << "  Ronda " << i << ": Clave actual: " << currentKey << std::endl;
            encrypt(std::to_string(currentKey), data, 8);
            hash = hashFunction(data, 8);
            std::cout << "  Ronda " << i << ": Hash generado: " << hash << std::endl;
            currentKey = reduceHash(hash, i);
            std::cout << "  Ronda " << i << ": Clave reducida: " << currentKey << std::endl;
        }

        std::cout << "Hash final: " << hash << " para la llave original: " << key << std::endl;
        rainbowTable[hash] = key; // Guardar el hash final y la llave original
    }

    std::cout << "Generación de la tabla rainbow completada." << std::endl;
}
// Buscar una llave en la tabla rainbow
unsigned long long searchRainbowTable(const std::unordered_map<std::string, unsigned long long>& rainbowTable, const unsigned char* cipher, int len, int chainLength) {
    std::string hash = hashFunction(cipher, len);
    
    for (int i = chainLength - 1; i >= 0; --i) {
        if (rainbowTable.find(hash) != rainbowTable.end()) {
            unsigned long long key = rainbowTable.at(hash);
            return key;
        }
        unsigned long long newKey = reduceHash(hash, i);
        unsigned char temp[8];
        memcpy(temp, cipher, 8);
        encrypt(std::to_string(newKey), temp, len);
        hash = hashFunction(temp, len);
    }

    return 0; // No encontrado
}

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    std::string userKey;
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

        // Pedir al usuario la clave para cifrar y la frase de comparación
        std::cout << "Introduce la clave para cifrar el texto: ";
        std::cin >> userKey;

        std::cout << "\nIniciando cifrado..." << std::endl;
        encrypt(userKey, cipher.data(), cipher.size());
        std::cout << "Cifrado terminado." << std::endl;

        std::cout << "\nTexto cifrado: ";
        for (unsigned char c : cipher) {
            printf("%02X", c);
        }

        std::cout << "\nIntroduce la frase para verificar el descifrado: ";
        std::cin.ignore();
        std::getline(std::cin, phrase);
        std::cout << std::endl;

        // Generar Rainbow Table
        unsigned long long lowerLimit = 0; // Límite inferior de llaves
        unsigned long long upperLimit = 99999; // Límite superior de llaves
        int chainLength = 1000; // Longitud de cadena en la tabla rainbow

        std::unordered_map<std::string, unsigned long long> rainbowTable;
        std::cout << "\nGenerando Rainbow Table..." << std::endl;
        generateRainbowTable(lowerLimit, upperLimit, chainLength, rainbowTable);
        std::cout << "Rainbow Table generada." << std::endl;
    }

    MPI_Finalize();
    return 0;
}

/**
compilar con:
mpic++ mpic++ -o rainbowtable rainbowtable.cpp -lssl -lcrypto


mpirun -np 4 ./rainbowtable

 */