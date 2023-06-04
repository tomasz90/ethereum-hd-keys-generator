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

    Serial.println("Ethereum pk");
    Serial.println(account.pk());

    Serial.println("Ethereum xpub");
    Serial.println(account.xpub());

    account.pub();
}

void loop() {
    delay(100);
}