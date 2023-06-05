#include <Arduino.h>
#include <unity.h>
#include "EthereumHDPrivateKey.h"

void compare_keys(
        const String &mnemonic,
        const String &path,
        const String &expectedPub,
        const String &expectedPrv,
        const String &expectedChecksumedAddress
) {
    EthereumHDPrivateKey hd(mnemonic);
    EthereumHDPrivateKey account = hd.derive(path);

    String pub = account.pub();
    String prv = account.prv();
    String addressChecksumed = account.addressChecksumed();

    TEST_ASSERT_TRUE(expectedPub == pub);
    TEST_ASSERT_TRUE(expectedPrv == prv);
    TEST_ASSERT_TRUE(expectedChecksumedAddress == addressChecksumed);
}

void should_return_right_keys() {
    String mnemonic = "puppy impulse govern shy salt despair deliver tuition cradle lend mosquito sugar";
    String path0 = "m/44'/60'/0'/0/0";
    String path1 = "m/44'/60'/0'/0/1";
    String path2 = "m/44'/60'/0'/0/2";
    String path3 = "m/44'/60'/0'/0/3";
    String path4 = "m/44'/60'/0'/0/4";
    String path5 = "m/44'/60'/0'/0/5";
    String path6 = "m/44'/60'/0'/0/6";
    String path7 = "m/44'/60'/0'/0/7";
    String path8 = "m/44'/60'/0'/0/8";
    String path9 = "m/44'/60'/0'/0/9";
    String path10 = "m/44'/60'/0'/0/10";

    String pub0 = "0x025e391d8650cfcc974e5d809b8dc9ac3cd885c03bbb52343c4cd84000e41e6ef1";
    String prv0 = "0x09e69394e935968d44003917da42d028c3515e3b37ddd60d8a1233ece54bd15a";
    String address0 = "0x58dddFB0946C6715bF6683d8Ea8d38baB16d771f";

    String pub1 = "0x0308ebdf108a2801572089eb25bf668b593887db6e6c397cd257dcb24fbfdbe46f";
    String prv1 = "0xcf61f43ca77619de367ebe4efae69a8a663089adf4b91c6e589906e55ea2cfca";
    String address1 = "0x19ae500f8e9d7db24018eB1b0bc1f8Bd53BD2B9a";

    String pub2 = "0x028742b95276ccc956afd1dfd6f2a7ca922a125798f990f20506562581a877d25c";
    String prv2 = "0x083623ea6f55be8f614395472da1b8eab607dc10299f93239a25c4cbccc724fc";
    String address2 = "0x9d6305CB4060a10eF176D4a542b305f8c0Ae8210";

    String pub3 = "0x03657870cbeac2d7d62af62e7a06777f9557855654aaedfe5fce099014acb11e36";
    String prv3 = "0x73f4816f800181b46a728371f6b40c911b6464dcee5f9dde384e182b946116bb";
    String address3 = "0xD0d498a68Ce833Cda879feD6481ac2f091B35B77";

    String pub4 = "0x027f679b6e8531f290a4641c03640db5f047357987e0313d3644d6353ba6d716b6";
    String prv4 = "0xedf08e9d43550099bab4444b43165fb1d0382edc4f99fcbb9a450511df7efa63";
    String address4 = "0xB7910de9eFc0cd85537c07c1237A403c3e3EfCD8";

    String pub5 = "0x0215556d84815e299dd57be78645c297cf0cd2ae3bb54e51903bbf6fcf9fd3a35b";
    String prv5 = "0xc713c1c87c237b4977321c77573c3f2904bb66aa554175393aa98d3537c28e85";
    String address5 = "0x854FAC1A548b0D67E47e58f2E1E34977B1365D6d";

    String pub6 = "0x02dc14cd98e2f229187943bc897b91e5340e52df085eaf2f50e3e32e9fe4d32071";
    String prv6 = "0xa9305ef7aef09b68a0ff36746b60389b1b557dd4234aad6d9ae3150682603162";
    String address6 = "0x354f8367dc0A6078ccBDf8d5218800853dE6bde3";

    String pub7 = "0x03c2e4e17d2cc8e4de7c8491c8850321104aac02dc97f6efd883aa4d477fb74df1";
    String prv7 = "0x2ff06d1d9d2b2a2ab09e5ccb446f1c7b128e2a5849f566723d314b4e67d75e6a";
    String address7 = "0x53583977a55614FFac080cA875949b3AC6587d4d";

    String pub8 = "0x02ed17bace36a49b6054422520e51f77970152abeb713a0ee3986c89be6380619f";
    String prv8 = "0xf6453e7c187d477f371331d4299359703bfd42cae853f50765f2946b7c7de5bd";
    String address8 = "0x1B97d51e87C0e84bfb526777F477dB95b4B70D3b";

    String pub9 = "0x031fee95b529c166d3dcb8b19281ab236228b54da617be51f673d6b4a805923824";
    String prv9 = "0x6046529f9d2127b55bc6d7e15a79e7af2e382e78a6b2e8f2ac04650d714b1925";
    String address9 = "0x85E6dDEE24cC74D407C133D195Dc187a1211d121";

    String pub10 = "0x029d8a1f7b08703bdeef4b0c075f4d20061e391b23b0b20811dfbc24b047ec82d6";
    String prv10 = "0xd2624fa487cef89110e56a1cc938dc8033fe9f33c180744dfbcc0b3fb070c793";
    String address10 = "0xc256e1Ac7F3Ec719967705d721DA55dc69952E2e";

    compare_keys(mnemonic, path0, pub0, prv0, address0);
    compare_keys(mnemonic, path1, pub1, prv1, address1);
    compare_keys(mnemonic, path2, pub2, prv2, address2);
    compare_keys(mnemonic, path3, pub3, prv3, address3);
    compare_keys(mnemonic, path4, pub4, prv4, address4);
    compare_keys(mnemonic, path5, pub5, prv5, address5);
    compare_keys(mnemonic, path6, pub6, prv6, address6);
    compare_keys(mnemonic, path7, pub7, prv7, address7);
    compare_keys(mnemonic, path8, pub8, prv8, address8);
    compare_keys(mnemonic, path9, pub9, prv9, address9);
    compare_keys(mnemonic, path10, pub10, prv10, address10);

}

void setup() {
    Serial.begin(115200);
    UNITY_BEGIN();
    RUN_TEST(should_return_right_keys);
    UNITY_END();
}

void loop() {}