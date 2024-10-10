#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <openssl/des.h>
#include <chrono>

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
    // Convertir la clave a 8 bytes para DES
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }

    // Establecer bits de paridad
    DES_set_odd_parity(&keyBlock);

    // Inicializar el calendario de claves
    DES_key_schedule schedule;
    DES_set_key(&keyBlock, &schedule); // Usar DES_set_key

    // Encriptar cada bloque de 8 bytes
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_ENCRYPT);
    }
}

void decrypt(unsigned long long key, unsigned char* data, int len) {
    // Convertir la clave a 8 bytes para DES
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }

    // Establecer bits de paridad
    DES_set_odd_parity(&keyBlock);

    // Inicializar el calendario de claves
    DES_key_schedule schedule;
    DES_set_key(&keyBlock, &schedule); // Usar DES_set_key

    // Desencriptar cada bloque de 8 bytes
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(data + i), (DES_cblock*)(data + i), &schedule, DES_DECRYPT);
    }
}

bool tryKey(unsigned long long key, const unsigned char* ciph, int len, const std::string& phrase) {
    std::vector<unsigned char> temp(ciph, ciph + len);
    decrypt(key, temp.data(), len);
    std::vector<unsigned char> decryptedData = removePadding(temp);
    decryptedData.push_back('\0'); // Asegurar terminación nula
    std::string decryptedText(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
    return decryptedText.find(phrase) != std::string::npos;
}

int main() {
    // Leer el texto desde el archivo input.txt
    std::ifstream inputFile("input.txt");
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

    // Convertir el texto a cifrar a un arreglo de unsigned char con padding
    std::vector<unsigned char> cipher(text.begin(), text.end());
    cipher = addPadding(cipher);

    // Pedir al usuario la llave para cifrar y la frase de comparación
    unsigned long long keyToEncrypt;
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
    
    std::cout << "Texto cifrado: ";
    for (auto c : cipher) {
        std::cout << std::hex << static_cast<int>(c) << " ";
    }
    std::cout << std::dec << std::endl;


    std::string phrase;
    std::cout << "\nIntroduce la frase para verificar el descifrado: ";
    std::cin.ignore(); // Limpiar el buffer de entrada
    std::getline(std::cin, phrase);

    std::cout << "\nIniciando búsqueda de la llave correcta..." << std::endl;


    // Medir el tiempo de ejecución
    auto start = std::chrono::high_resolution_clock::now();

    // Búsqueda de la llave correcta
    unsigned long long upper = 1ULL << 56; // Upper bound for DES keys (2^56)
    unsigned long long found = 0;
    for (unsigned long long i = 0; i < upper; ++i) {
        if (tryKey(i, cipher.data(), cipher.size(), phrase)) {
            found = i;
            break;
        }
        // Opcional: Mostrar progreso cada cierto número de iteraciones
        
        if (i % 1000000 == 0) {
            std::cout << "\t⇨ Progreso: " << i << " millones de claves probadas." << std::endl;
        }
        
    }

    // Medir el tiempo final
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    // Mostrar el resultado
    if (found != 0 || keyToEncrypt == 0) { // Ajuste para permitir que la clave 0 sea encontrada
        decrypt(found, cipher.data(), cipher.size());
        std::vector<unsigned char> decryptedData(cipher.begin(), cipher.end());
        decryptedData = removePadding(decryptedData);
        decryptedData.push_back('\0'); // Asegurar terminación nula
        std::string decryptedText(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
        std::cout << "\nLa llave correcta es: " << found << std::endl;
        std::cout << "El texto descifrado es: " << decryptedText << std::endl;
    } else {
        std::cout << "No se encontró una llave válida." << std::endl;
    }

    // Mostrar el tiempo tomado
    std::cout << "Tiempo tomado para encontrar la llave: " << duration.count() << " segundos" << std::endl;

    return 0;
}

/**

To compile it:

g++ -o bf_sequential bf_seq.cpp -lssl -lcrypto

./bf_sequential


 */