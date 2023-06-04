//
// Created by Tomasz Kulig on 04/06/2023.
//

#ifndef UNTITLED_ETHEREUMHDPRIVATEKEY_H
#define UNTITLED_ETHEREUMHDPRIVATEKEY_H


#include "Bitcoin.h"

class EthereumHDPrivateKey : HDPrivateKey {

public:
    EthereumHDPrivateKey(const String &mnemonic);
    EthereumHDPrivateKey(const String &mnemonic, const String &password);

    String _xprv() const;
    EthereumHDPrivateKey _derive(const char * path) const;
    String pk() const;
};


#endif //UNTITLED_ETHEREUMHDPRIVATEKEY_H
