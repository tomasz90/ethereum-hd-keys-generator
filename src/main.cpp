#include "Bitcoin.h"
#include "EthereumHDPrivateKey.h"

void setup() {
    Serial.begin(115200);
    String mnemonic("puppy impulse govern shy salt despair deliver tuition cradle lend mosquito sugar");

    EthereumHDPrivateKey hd(mnemonic);

    Serial.println("Mnemonic:");
    Serial.println(mnemonic);

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
}

void loop() {
    delay(100);
}