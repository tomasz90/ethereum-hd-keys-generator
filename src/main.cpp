/*
 * This example shows how to derive master private key from the recovery seed
 * Generate a random recovery seed i.e. on https://iancoleman.io/bip39/
 * and check the master private key, account private key, account public key
 * and first address.
 */
#include <cstring>
#include "Bitcoin.h"

void printHD(String mnemonic){

    HDPrivateKey hd(mnemonic, "");

    if(!hd){ Serial.println("Invalid xpub"); return;}

    Serial.println("Mnemonic:");
    Serial.println(mnemonic);
    Serial.println("Root private key:");
    Serial.println(hd);

    Serial.println("First account:");
    HDPrivateKey account = hd.derive("m/44'/60'/0'/0/0");
    Serial.println(account.address());

    Serial.println("First private key:");

    String xprv = account.xprv();

    uint8_t arr[78] = { 0 };
    size_t l = fromBase58Check(xprv, arr, sizeof(arr));

    if(l != sizeof (arr)) {
        throw std::runtime_error("Invalid conversion from xprv to bytes");
    }

    uint8_t last32Bytes[32];

    std::memcpy(last32Bytes, arr + 78 - 32, sizeof(last32Bytes));

    String ethereumPk = toHex(last32Bytes, sizeof last32Bytes);

    Serial.println("Ethereum pk");
    Serial.println(ethereumPk);

    Serial.println("\n");
}

void setup() {
    Serial.begin(115200);
    printHD("puppy impulse govern shy salt despair deliver tuition cradle lend mosquito sugar");
}

void loop() {
    delay(100);
}