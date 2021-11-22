echo "if docker image doesnt exist then build docker image"
echo 'build docker image from scratch
cd contrib/android
docker build -t electrum-android-builder-img .
cd ../../
'
echo "script will pause for 5 seconds while you think about this crtl-C to quit script to build docker image"
sleep 5s

#    c4pt/electrum-android

echo 'running docker image for environment to build android app as an apk'
echo ""
echo ""
docker run -it -d --rm \
    -v $PWD:/home/user/wspace/electrum \
    -v $PWD/.buildozer/.gradle:/home/user/.gradle \
    --workdir /home/user/wspace/electrum \
    electrum-android-builder-img
echo "^^^^ first 4 or 5 numbers or letters of this hash as <docker_vm_hash>" 
echo "->   docker exec -it <docker_vm_hash> bash"
echo ""
echo ""
echo "once in the shell run these commands"
echo ""
echo ""
sleep 1s
echo "sudo -i"
echo "pip install cython buildozer "
echo "cd /home/user/wspace/electrum"
echo ""
echo "speed-up build time with parallel concurrent build using multi cores change max=8 to your needs for 8 cores etc"
echo ""
echo ""
echo 'export GRADLE_OPTS="-Dorg.gradle.parallel=true -Dorg.gradle.workers.max=8 -Dorg.gradle.daemon=true -Dorg.gradle.configureondemand=true"'
echo "" 
echo ""
echo "pip install -r contrib/deterministic-build/requirements.txt"
echo "./contrib/android/make_apk"
echo ".apk will be located in dist"
