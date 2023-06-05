# EthereumHDKeysGenerator

Library that allows to generate private keys and addresses of ethereum account based on mnemonic and derivation path. Unfortunately there was no such project available for embedded devices written i C++ so I created this. Library is very small, cause it is haviley dependent on [uBitcoin](https://github.com/micro-bitcoin/uBitcoin), generating keys in Eth is quite similar to generation of Bitcoin keys, so it was reasonable to use external resources.

If you are using ESP32 you may meet error about multiple definition of functions "hmac_sha256", these are independet functions - one is from uBitcoin, the second one is from ESP32 libraries itself. For now you have to rename it in uBitoin ex. "hmac_sha256_" but I just rose a ticket about this in uBitcoin repo.

This repo is still in progress, I am writing  bunch of unit tests.  <br />  <br />
**Please treat is as "very" ALPHA software and do not use it with real funds, but rather use testnet ETH.** <br />  <br />
Feel free to rise PRs. <br />  <br />
Here is an example sketch:

```cpp

#include "EthereumHDPrivateKey.h"

void setup() {
    Serial.begin(115200);
    String mnemonic = "puppy impulse govern shy salt despair deliver tuition cradle lend mosquito sugar";

    Serial.println("Mnemonic:");
    Serial.println(mnemonic);

    EthereumHDPrivateKey hd(mnemonic);
    EthereumHDPrivateKey account = hd.derive("m/44'/60'/0'/0/0");

    Serial.println("xprv:");
    Serial.println(account.xprv());

    Serial.println("xpub:");
    Serial.println(account.xpub());

    Serial.println("pub:");
    Serial.println(account.pub());

    // probably these are functions that you are interested in
    Serial.println("prv:");
    Serial.println(account.prv());

    Serial.println("address:");
    Serial.println(account.address());
    
    Serial.println("checksumed address:");
    Serial.println(account.addressChecksumed());
}

void loop() {
    delay(100);
}

```
