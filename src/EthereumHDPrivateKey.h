#ifndef ETHEREUMHDPRIVATEKEY_H
#define ETHEREUMHDPRIVATEKEY_H

#include <cstdint>
#include <cstddef>
#include "Bitcoin.h"

class EthereumHDPrivateKey : HDPrivateKey {

public:
    explicit EthereumHDPrivateKey(const HDPrivateKey& hd);
    explicit EthereumHDPrivateKey(const String &mnemonic);
    EthereumHDPrivateKey(const String &mnemonic, const String &password);

    EthereumHDPrivateKey derive(const String &path) const;
    String xprv() const;
    String xpub() const;
    String pub() const;
    String prv() const;
    String address() const;

private:
    void prvRaw(uint8_t *result, uint8_t resultSize) const;
};


#endif //ETHEREUMHDPRIVATEKEY_H
