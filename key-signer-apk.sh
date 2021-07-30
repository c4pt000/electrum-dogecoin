#!/bin/bash

echo '/home/c4pt/opt/android-sdk/tools/emulator @testAVD &'
echo "STARTING KEYSIGN GENERATOR FOR UNSIGNED APK"
echo "install nodejs, npm for 'npm i -g randomstring' "
npm i -g randomstring


randomstring
cp -rf dist/Electrum-4.1.5.0-arm64-v8a-release-unsigned.apk digitalpay-unsign.apk
rm -rf my-release-key.jks
keytool -genkey -v -keystore my-release-key.jks -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
/home/c4pt/opt/android-sdk/build-tools/29.0.3/apksigner sign --ks my-release-key.jks --out digitalpay-prod-out-logo-current.apk digitalpay-unsign.apk
cp -rf digitalpay-prod-out-logo-current.apk dogecoin.apk
