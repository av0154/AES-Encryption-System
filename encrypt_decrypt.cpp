#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>

class AES {
public:
    std::string encrypt(const std::string& plainText, const std::string& key) {
        CryptoPP::AES::Encryption aesEncryption((CryptoPP::byte*)key.data(), AES::DEFAULT_KEYLENGTH);
        CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

        std::string cipherText;
        CryptoPP::StreamTransformationFilter filter(cbcEncryption, new CryptoPP::StringSink(cipherText));
        filter.Put(reinterpret_cast<const unsigned char*>(plainText.data()), plainText.size() + 1); // Include null terminator
        filter.MessageEnd();

        return cipherText;
    }

    std::string decrypt(const std::string& cipherText, const std::string& key) {
        CryptoPP::AES::Decryption aesDecryption((CryptoPP::byte*)key.data(), AES::DEFAULT_KEYLENGTH);
        CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

        std::string decryptedText;
        CryptoPP::StreamTransformationFilter filter(cbcDecryption, new CryptoPP::StringSink(decryptedText));
        filter.Put(reinterpret_cast<const unsigned char*>(cipherText.data()), cipherText.size());
        filter.MessageEnd();

        return decryptedText;
    }

private:
    static constexpr size_t DEFAULT_KEYLENGTH = 16; // 128 bits
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0}; // Initialize IV with zeros
};

int main() {
    AES aes;
    std::string plainText;
    std::cout << "Enter plain text: ";
    std::getline(std::cin, plainText);

    std::string key = "0123456789abcdef"; // 16 bytes

    std::string cipherText = aes.encrypt(plainText, key);
    std::cout << "Cipher Text: " << cipherText << std::endl;

    std::string decryptedText = aes.decrypt(cipherText, key);
    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    return 0;
}
