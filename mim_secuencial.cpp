#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <openssl/des.h>
#include <chrono>
#include <cmath>
#include <cstring>
#include <string>

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

int main() {
    unsigned long long key1 = 0, key2 = 0;
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> ciphertext;
    std::string phrase;

    // Leer el texto desde el archivo input.txt
    std::ifstream inputFile("input.txt", std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error: no se pudo abrir el archivo input.txt" << std::endl;
        return 1;
    }

    std::string text((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();
    if (text.empty()) {
        std::cerr << "El archivo input.txt está vacío." << std::endl;
        return 1;
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

    // Mostrar el texto cifrado en formato hexadecimal
    std::cout << "\nTexto cifrado: ";
    for (unsigned char c : ciphertext) {
        printf("%02X", c);
    }
    std::cout << std::endl;

    // Solicitar frase para verificar el descifrado (opcional)
    std::cout << "\nIntroduce la frase para verificar el descifrado: ";
    std::cin.ignore(); // Limpiar el buffer de entrada
    std::getline(std::cin, phrase);

    std::cout << "\nIniciando ataque Meet-in-the-Middle..." << std::endl;

    unsigned long long maxKey = (1ULL << 24);

    // Fase 1: Generar la tabla E(K1, P)
    std::unordered_map<std::string, unsigned long long> table;

    // Medir el tiempo de ejecución
    auto start_time = std::chrono::high_resolution_clock::now();

    std::cout << "Generando tabla E(K1, P) para todas las posibles K1..." << std::endl;
    for (unsigned long long k = 0; k < maxKey; ++k) {
        std::vector<unsigned char> temp = plaintext;
        encrypt(k, temp.data(), temp.size());
        std::string hash(reinterpret_cast<char*>(temp.data()), temp.size());
        table[hash] = k;

        // Opcional: Mostrar progreso
        if (k % 1000000 == 0 && k != 0) {
            std::cout << "Procesadas " << k << " claves K1..." << std::endl;
        }
    }
    std::cout << "Tabla E(K1, P) generada." << std::endl;

    // Fase 2: Buscar coincidencias con D(K2, C)
    unsigned long long foundK1 = 0, foundK2 = 0;
    bool found = false;

    std::cout << "Buscando coincidencias con D(K2, C)..." << std::endl;
    for (unsigned long long k = 0; k < maxKey; ++k) {
        std::vector<unsigned char> temp = ciphertext;
        decrypt(k, temp.data(), temp.size());
        std::string hash(reinterpret_cast<char*>(temp.data()), temp.size());

        auto it = table.find(hash);
        if (it != table.end()) {
            foundK1 = it->second;
            foundK2 = k;
            found = true;
            break;
        }

        // Opcional: Mostrar progreso
        if (k % 1000000 == 0 && k != 0) {
            std::cout << "Procesadas " << k << " claves K2..." << std::endl;
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
        std::cout << "\nNo se encontraron las llaves." << std::endl;
        std::cout << "Tiempo de ejecución: " << duration.count() << " segundos" << std::endl;
    }

    return 0;
}

// Compilación:
// g++ -o mim_secuencial mim_secuencial.cpp -lssl -lcrypto

// Ejecución:
// ./mim_secuencial