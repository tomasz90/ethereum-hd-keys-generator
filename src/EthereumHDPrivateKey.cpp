#include "EthereumHDPrivateKey.h"
#include "utility/trezor/memzero.h"
#include "EthereumHDPublicKey.h"
#include "utility/trezor/sha3.h"

EthereumHDPrivateKey::EthereumHDPrivateKey(const String &mnemonic) : EthereumHDPrivateKey(mnemonic, "") {}

EthereumHDPrivateKey::EthereumHDPrivateKey(const String &mnemonic, const String &password) : HDPrivateKey(mnemonic,password) {}

EthereumHDPrivateKey::EthereumHDPrivateKey(const HDPrivateKey &hd) : HDPrivateKey(hd) {}

EthereumHDPrivateKey EthereumHDPrivateKey::derive(const char *path) const {
    HDPrivateKey hd = HDPrivateKey::derive(path);
    return EthereumHDPrivateKey(hd);
}

String EthereumHDPrivateKey::xprv() const {
    return HDPrivateKey::xprv();
}

String EthereumHDPrivateKey::prv() const {
    uint8_t last32Bytes[32] = {0};
    prvRaw(last32Bytes, sizeof(last32Bytes));

    String prv = "0x" + toHex(last32Bytes, sizeof(last32Bytes));
    memzero(&last32Bytes, sizeof(last32Bytes));
    return prv;
}

String EthereumHDPrivateKey::xpub() const {
    return HDPrivateKey::xpub();
}

String EthereumHDPrivateKey::pub() const {
    uint8_t xpubRaw[78];
    EthereumHDPublicKey pubKey = EthereumHDPublicKey(HDPrivateKey::xpub());
    pubKey.to_bytes(xpubRaw, sizeof(xpubRaw));

    uint8_t pubRaw[33] = {0};
    fromBase58(this->xprv(), pubRaw, sizeof(pubRaw));

    memcpy(pubRaw, xpubRaw + sizeof(xpubRaw) - sizeof(pubRaw), sizeof(pubRaw));
    memzero(&xpubRaw, sizeof(xpubRaw));

    return "0x" + toHex(pubRaw, sizeof(pubRaw));
}

String EthereumHDPrivateKey::address() const {

    HDPublicKey pubKey = HDPrivateKey::xpub();

    uint8_t hash[32] = {0};
#if USE_KECCAK
    keccak_256(pubKey.point, sizeof(pubKey.point), hash);
#endif

    uint8_t rawAddress[20] = {0};

    memcpy(rawAddress, hash + sizeof(hash) - sizeof(rawAddress), sizeof(rawAddress));
    memzero(&hash, sizeof(hash));

    return "0x" + toHex(rawAddress, sizeof(rawAddress));
}

void EthereumHDPrivateKey::prvRaw(uint8_t *result, uint8_t resultSize) const {
    uint8_t xprvRaw[78] = {0};
    size_t l = fromBase58Check(this->xprv(), xprvRaw, sizeof(xprvRaw));

    if (l != sizeof(xprvRaw)) {
        Serial.println("Invalid xprv conversion");
        return;
    }
    memcpy(result, xprvRaw + sizeof(xprvRaw) - resultSize, resultSize);
    memzero(&xprvRaw, sizeof(xprvRaw));
}
