//
// Created by Tomasz Kulig on 04/06/2023.
//

#ifndef UNTITLED_ETHEREUMHDPRIVATEKEY_H
#define UNTITLED_ETHEREUMHDPRIVATEKEY_H


#include "Bitcoin.h"

class EthereumHDPrivateKey : HDPrivateKey {

public:
    explicit EthereumHDPrivateKey(const HDPrivateKey& hd);
    explicit EthereumHDPrivateKey(const String &mnemonic);
    EthereumHDPrivateKey(const String &mnemonic, const String &password);

    String xprv() const;
    EthereumHDPrivateKey derive(const char * path) const;
    String pk() const;
    void pkRaw(uint8_t *result, uint8_t resultSize) const;
};


#endif //UNTITLED_ETHEREUMHDPRIVATEKEY_H
