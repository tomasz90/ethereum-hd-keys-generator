#include "Bitcoin.h"
#include "EthereumHDPrivateKey.h"
#include "utility/trezor/memzero.h"

void printHD(String mnemonic) {

    HDPrivateKey hd(mnemonic, "");

    Serial.println("Mnemonic:");
    Serial.println(mnemonic);

    HDPrivateKey account = hd.derive("m/44'/60'/0'/0/0");

    Serial.println("xprv:");
    String xprv = account.xprv();

    uint8_t arr[78] = {0};
    size_t l = fromBase58Check(xprv, arr, sizeof(arr));

    if (l != sizeof(arr)) {
        Serial.println("Invalid xprv conversion");
        return;
    }

    uint8_t last32Bytes[32];

    memcpy(last32Bytes, arr + sizeof(arr) - sizeof(last32Bytes), sizeof(last32Bytes));
    memzero(&arr, sizeof(arr));

    String ethereumPk = toHex(last32Bytes, sizeof(last32Bytes));

    Serial.println("Ethereum pk");
    Serial.println(ethereumPk);
}

void setup() {
    Serial.begin(115200);
    printHD("puppy impulse govern shy salt despair deliver tuition cradle lend mosquito sugar");
}

void loop() {
    delay(100);
}