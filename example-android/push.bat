@echo off

::adb push libs/x86_64/KittyMemoryExExample /data/local/tmp
::adb push libs/x86/KittyMemoryExExample /data/local/tmp
adb push libs/arm64-v8a/KittyMemoryExExample /data/local/tmp
::adb push libs/armeabi-v7a/KittyMemoryExExample /data/local/tmp


adb shell "su -c 'kill $(pidof KittyMemoryExExample) > /dev/null 2>&1'"
adb shell "su -c 'chmod +x /data/local/tmp/KittyMemoryExExample'"

adb shell "su -c './/data/local/tmp/KittyMemoryExExample com.kiloo.subwaysurf'"

pause