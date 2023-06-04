/*
 * This example shows how to derive master private key from the recovery seed
 * Generate a random recovery seed i.e. on https://iancoleman.io/bip39/
 * and check the master private key, account private key, account public key
 * and first address.
 */
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

    uint8_t arr[112] = { 0 };
    size_t l = fromBase58Check(xprv, arr, sizeof(arr));

    String ethereumPk = toHex(arr, 32);

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