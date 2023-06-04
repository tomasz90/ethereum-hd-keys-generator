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
    pkRaw(last32Bytes);
    return toHex(last32Bytes, sizeof(last32Bytes));
}

void EthereumHDPrivateKey::pkRaw(uint8_t last32Bytes[32]) const {
    uint8_t arr[78] = {0};
    size_t l = fromBase58Check(this->xprv(), arr, sizeof(arr));

    if (l != sizeof(arr)) {
        Serial.println("Invalid xprv conversion");
        return;
    }

    memcpy(last32Bytes, arr + sizeof(arr) - 32, 32);
    memzero(&arr, sizeof(arr));
}
