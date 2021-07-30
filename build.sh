#!/bin/bash
echo '  gradle clean :wallet:assembleProdRelease'

echo '/home/c4pt/opt/android-sdk/tools/emulator @testAVD &'

randomstring
cp -rf dist/Electrum-4.1.5.0-armeabi-v7a-release-unsigned.apk digitalpay-unsign.apk
rm -rf my-release-key.jks
keytool -genkey -v -keystore my-release-key.jks -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
/home/c4pt/opt/android-sdk/build-tools/29.0.3/apksigner sign --ks my-release-key.jks --out digitalpay-prod-out-logo-current.apk digitalpay-unsign.apk
cp -rf digitalpay-prod-out-logo-current.apk dogecoin.apk
