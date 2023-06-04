//
// Created by Tomasz Kulig on 04/06/2023.
//

#include "EthereumHDPrivateKey.h"
#include "utility/trezor/bip39.h"
#include "utility/trezor/memzero.h"

EthereumHDPrivateKey::EthereumHDPrivateKey(const String &mnemonic) : EthereumHDPrivateKey(mnemonic, "") {}

EthereumHDPrivateKey::EthereumHDPrivateKey(const String &mnemonic, const String &password) : HDPrivateKey(mnemonic, password) {
//    if(mnemonic_check(mnemonic.c_str())) {
//        Serial.println("Invalid mnemonic");
//        throw std::invalid_argument("");
//    }
}

String EthereumHDPrivateKey::_xprv() const {
    return HDPrivateKey::xprv();
}

EthereumHDPrivateKey EthereumHDPrivateKey::_derive(const char *path) const {
    HDPrivateKey hd = HDPrivateKey::derive(path);
    return (EthereumHDPrivateKey)hd;
}

String EthereumHDPrivateKey::pk() const {
    uint8_t arr[78] = {0};
    size_t l = fromBase58Check(this->xprv(), arr, sizeof(arr));

    if (l != sizeof(arr)) {
        Serial.println("Invalid xprv conversion");
        return "";
    }

    uint8_t last32Bytes[32];

    memcpy(last32Bytes, arr + sizeof(arr) - sizeof(last32Bytes), sizeof(last32Bytes));
    memzero(&arr, sizeof(arr));

    return toHex(last32Bytes, sizeof(last32Bytes));
}
