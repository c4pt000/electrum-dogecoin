
pulled from here originally https://gist.github.com/Guhan-SenSam/35c5ed7da254a7c0141e6a8b6101eb33

# Introduction

Recently Google made it compulsory that all new apps must be uploaded not as .apk files but as .aab files. Till just recently the tool Buildozer was only able to compile your python applications to `.apk` but recent changes have allowed us to compile to `.aab` format. This is an instruction set that can be used to create a release `.aab`.

# What is an AAB
 The new `.aab` format may be a little confusing. `.aab` stands for app bundles and consists of a bundle of apk's within it. When you upload an `aab` to the playstore you are basically uploading a bunch of `apk`. PlayStore then based on the device that is downloading your application will generate the required `apk` based on that devices architecture and other parameters.

 The introduction of `.aab` doesn't mean that `.apk` are no longer useful. `.aab` are only used for releases where as `.apk` are still used for testing your application and sharing it with others to directly install(not through the store).

 > Note: Test your applications using only `.apk` not using `.aab`.

 # Instrutions

We are going to be making a release version of the `.aab` which means the `.aab` needs to be signed. For instructions on how to sign an `.aab` check here and follow till step 6 and then come back here.

[How to sign a release aab/apk](https://gist.github.com/Guhan-SenSam/fa4ed215ef3419e7b3154de5cb71f641)

> Note: Don't close the terminal after following the steps in the above link. If you accidently close the terminal repeat the steps from the beginning

Now that you have got things ready to sign an `.aab`, it's time to actually create the `.aab` and sign it. Follow the following steps.

1. Run this command to clone the version of buildozer that supports `.aab` creation.
`pip install git+https://github.com/misl6/buildozer.git@feat/aab-support`

2. After buildozer is done installing, using the same terminal you used in the link given above, navigate to the root of your program directory.

3. If you have already used buildozer before and there is a `buildozer.spec` file inside your project directory, delete it.

4. Now run `buildozer init` in the terminal.

5. Open the generated `buildozer.spec` file in any text editor and find the line
```
# (list) The Android archs to build for, choices: armeabi-v7a, arm64-v8a, x86, x86_64
android.archs = arm64-v8a
```
This parameters controls what different architectures you can compile your application for. My preference is to target both 64 and 32 bit ARM processors. Thus it would look like this for me.

    `android.archs = arm64-v8a, armeabi-v7a`

    `android.archs` was newly added for `aab` support. Before buildozer supported `aab` creation, this parameter was called `android.arch` meaning it only supported a single architecture. Due to this change the old `buildozer.spec` files will not work with this function and it is why we reran `buildozer init` at the start.

    > Note: There are more new parameters that control `aab` creation that will not be present in the older `buildozer.spec` files. I am not going to talk about all of them, just be aware that this is not the only change

    `android.archs` is now a list where you can enter just one or as many architectures you want. Buildozer will compile for them all and package them into the `.aab`.

6. Locate this parameter in your `buildozer.spec`
```
# (str) The format used to package the app for release mode (aab or apk).
android.release_artifact = aab
```
and make sure that it is uncommented and set to aab like shown above. This means that buildozer will compile to an `.aab` format for release build. If you want to compile a release apk (Google still allows aps to be updated through apk) then change this to `apk`
> Note: Whenever you make a debug build in the `aab` version of buildozer, you will only get an apk. This is correct behavior as for testing your app you should only use `.apk`

7. Change the p4a version to develop. i.e find this parameter and change it to below
```
p4a.branch = develop
```

8. In case you have used buildozer before delete the `.buildozer` folder inside your project directory. If you don't see the folder make sure you have turned on show hidden files in your file browser.

9. In the terminal where you entered your keystore info(as in the steps listed at the top of this document) run this command
`buildozer -v android release`

10. Now sit back and relax as buildozer compiles your `.aab`. This may take a long time(depends on your system) as buildozer needs to compile for all the individual architectures that you entered. After the first compile subsequent compiles will be much faster.

# Some Suggestions

I have released one app on the store so far with two more inline. I learnt a lot of this through pure trial and error. I understand if this may seem complicated at first but you will get better at don't worry. Here are some suggestions I would have for you before releasing your app on the store.

1. Be patient. I realize that your filled with joy that you are finally done with your app, and you just want to get it out there. SLOW DOWN!! The final release phase is the most critical and you have to make sure everything is perfect before your app goes live. Take your time, try uploading your app to a test track and see if everything works, check your apps for bugs etc.

2. Before going for final release, deploy your app to a test track at least once. You can add yourself to the testing device group(meaning only you will see the app on the Playstore). Wait 15-30 mins and you should see the app on the store on your phone. Download it and check if everything is working perfect. After you are satisfied then go for the final release.

3. Whenever running your final compile. Delete the `.buildozer` file and run the compile from the beginning. It may take longer but it ensures that no dependencies where missed by buildozer.


# About

1. [Twitter handle](https://twitter.com/gsensam?lang=en)
2. [Instagram](https://www.instagram.com/gravisoft_solutions/)
3. [My Apps](https://play.google.com/store/apps/dev?id=8582165811450724246)
