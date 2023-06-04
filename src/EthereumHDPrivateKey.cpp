#include <sstream>
#include <iomanip>
#include "EthereumHDPrivateKey.h"
#include "utility/trezor/bip39.h"
#include "utility/trezor/memzero.h"

EthereumHDPrivateKey::EthereumHDPrivateKey(const String &mnemonic) : EthereumHDPrivateKey(mnemonic, "") {}

EthereumHDPrivateKey::EthereumHDPrivateKey(const String &mnemonic, const String &password) : HDPrivateKey(mnemonic, password) {}

EthereumHDPrivateKey::EthereumHDPrivateKey(const HDPrivateKey &hd): HDPrivateKey(hd) {}

String EthereumHDPrivateKey::xprv() const {
    return HDPrivateKey::xprv();
}

EthereumHDPrivateKey EthereumHDPrivateKey::derive(const char *path) const {
    HDPrivateKey hd = HDPrivateKey::derive(path);
    return EthereumHDPrivateKey(hd);
}

String EthereumHDPrivateKey::pk() const {
    uint8_t last32Bytes[32] = {0};
    pkRaw(last32Bytes, sizeof(last32Bytes));
    return toHex(last32Bytes, sizeof(last32Bytes));
}

void EthereumHDPrivateKey::pkRaw(uint8_t *result, uint8_t resultSize) const {
    uint8_t arr[78] = {0};
    size_t l = fromBase58Check(this->xprv(), arr, sizeof(arr));

    if (l != sizeof(arr)) {
        Serial.println("Invalid xprv conversion");
        return;
    }
    Serial.println(sizeof result);
    memcpy(result, arr + sizeof(arr) - resultSize, resultSize);
    memzero(&arr, sizeof(arr));
}

String EthereumHDPrivateKey::pub() const {
    uint8_t last32Bytes[78];
    HDPublicKey pub = HDPrivateKey::xpub();
    pub.to_bytes(last32Bytes, sizeof(last32Bytes));


    uint8_t arr[33] = {0};
    size_t l = fromBase58Check(this->xprv(), arr, sizeof(arr));

    memcpy(arr, last32Bytes + sizeof(last32Bytes) - 33, 33);


    printBytes(arr, sizeof(arr));


    uint8_t digest[64] = {0};

    keccak_256(last32Bytes, sizeof(last32Bytes), digest);

    printBytes(digest, sizeof(digest));

    return "";
}

String EthereumHDPrivateKey::xpub() const {
    return HDPrivateKey::xpub();
}

void EthereumHDPrivateKey::printBytes(uint8_t *arr, uint8_t arrSize) const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (int i = 0; i < arrSize; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(arr[i]);
    }
    Serial.println(oss.str().c_str());
}