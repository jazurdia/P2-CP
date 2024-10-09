#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <openssl/des.h>
#include <chrono>

void encrypt(long key, unsigned char* ciph, int len) {
    // Convert the long key to 8 bytes for DES
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }

    // Set parity bits
    DES_set_odd_parity(&keyBlock);

    // Initialize the key schedule
    DES_key_schedule schedule;
    DES_set_key_checked(&keyBlock, &schedule);

    // Encrypt the plaintext
    DES_ecb_encrypt((DES_cblock*)ciph, (DES_cblock*)ciph, &schedule, DES_ENCRYPT);
}

void decrypt(long key, unsigned char* ciph, int len) {
    // Convert the long key to 8 bytes for DES
    DES_cblock keyBlock;
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (8 * (7 - i))) & 0xFF;
    }

    // Set parity bits
    DES_set_odd_parity(&keyBlock);

    // Initialize the key schedule
    DES_key_schedule schedule;
    DES_set_key_checked(&keyBlock, &schedule);

    // Decrypt the ciphertext
    DES_ecb_encrypt((DES_cblock*)ciph, (DES_cblock*)ciph, &schedule, DES_DECRYPT);
}

bool tryKey(long key, const unsigned char* ciph, int len, const std::string& phrase) {
    std::vector<unsigned char> temp(ciph, ciph + len);
    decrypt(key, temp.data(), len);
    temp.push_back('\0'); // Ensure null termination
    std::string decryptedText(reinterpret_cast<const char*>(temp.data()), len);
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

    // Convertir el texto a cifrar a un arreglo de unsigned char
    std::vector<unsigned char> cipher(text.begin(), text.end());

    // Pedir al usuario la llave para cifrar y la frase de comparación
    long keyToEncrypt;
    std::cout << "Introduce la llave para cifrar el texto (entero): ";
    std::cin >> keyToEncrypt;

    std::string phrase;
    std::cout << "Introduce la frase para verificar el descifrado: ";
    std::cin.ignore(); // Limpiar el buffer de entrada
    std::getline(std::cin, phrase);

    // Cifrar el texto usando la llave proporcionada
    encrypt(keyToEncrypt, cipher.data(), cipher.size());

    // Mostrar el texto cifrado
    std::cout << "Texto cifrado: ";
    for (auto c : cipher) {
        std::cout << std::hex << static_cast<int>(c) << " ";
    }
    std::cout << std::dec << std::endl;

    // Medir el tiempo de ejecución
    auto start = std::chrono::high_resolution_clock::now();

    // Búsqueda de la llave correcta
    long upper = (1L << 56); // Upper bound for DES keys (2^56)
    long found = 0;
    for (long i = 0; i < upper; ++i) {
        if (tryKey(i, cipher.data(), cipher.size(), phrase)) {
            found = i;
            break;
        }
    }

    // Medir el tiempo final
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    // Mostrar el resultado
    if (found != 0) {
        decrypt(found, cipher.data(), cipher.size());
        std::cout << "La llave correcta es: " << found << std::endl;
        std::cout << "El texto descifrado es: " << reinterpret_cast<char*>(cipher.data()) << std::endl;
    } else {
        std::cout << "No se encontró una llave válida." << std::endl;
    }

    // Mostrar el tiempo tomado
    std::cout << "Tiempo tomado para encontrar la llave: " << duration.count() << " segundos" << std::endl;

    return 0;
}
