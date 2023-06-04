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
    String xpub() const;

    EthereumHDPrivateKey derive(const char * path) const;
    String pk() const;
    void pkRaw(uint8_t *result, uint8_t resultSize) const;

    String pub() const;

    void printBytes(uint8_t *arr, uint8_t arrSize);

    void printBytes(uint8_t *arr, uint8_t arrSize) const;
};


#endif //UNTITLED_ETHEREUMHDPRIVATEKEY_H
