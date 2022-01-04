docker run -it -d \
    -v /opt/electrum-dogecoin:/opt/wine64/drive_c/electrum \
    --rm \
    --workdir /opt/wine64/drive_c/electrum/contrib/build-wine \
    electrum-dogecoin-build-win \
    
