//
// Created by Tomasz Kulig on 05/06/2023.
//

#ifndef UNTITLED_ETHEREUMHDPUBLICKEY_H
#define UNTITLED_ETHEREUMHDPUBLICKEY_H


#include <cstdint>
#include <cstddef>
#include "../.pio/libdeps/esp32dev/uBitcoin/src/Bitcoin.h"

class EthereumHDPublicKey : HDPublicKey {
public:
    explicit EthereumHDPublicKey(const HDPublicKey& hd);

    size_t to_bytes(uint8_t *arr, size_t len) const;
};


#endif //UNTITLED_ETHEREUMHDPUBLICKEY_H
