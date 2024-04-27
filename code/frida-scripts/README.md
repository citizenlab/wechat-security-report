## Dynamic analysis setup
This will walk you through setup for WeChat mobile app on Android (for either an emulated or rooted
device), and setup for both Wireshark and Frida instrumentation for analysis.
### 1. ADB setup
Install [`platform-tools`](https://developer.android.com/tools/releases/platform-tools).

 * If emulating, in Android Studio, create new image of Pixel 5 API 32 with at least 5GB internal storage, optionally
more in SD card if you’d like.
 * If using real device, make sure device is rooted and USB debugging is on. Connect using USB.

If successful, `adb devices` should list either the emulated or the rooted device.
Run `adb root`.

### 2. WeChat setup
Download Wechat APK compiled form arm64-v8a / armeabi-v7a (assuming wechat.apk) from the official
[version list](https://weixin.qq.com/cgi-bin/readtemplate?lang=zh_CN&t=weixin_faq_list).

We are looking at version v8.0.49.

```
adb install wechat.apk
```

### 3. Network inspection setup
`tcpdump` should already be installed on the Android device if the version is recent. Similarly, on
the host device, if `android-platform-tools` is installed then `androiddump` should be installed as
well.

On host computer, ensure `tshark -D` lists an android interface. For an emulator this should be
something like `android-tcpdump-any-emulator-5554`.

You should then be able to sniff all traffic on the Android device with Wireshark by selecting this interface.
Alternatively, you can run `tcpdump` on the device:

```
adb shell "tcpdump -n -s 0 -w /sdcard/netlog.pcapng"
adb pull /sdcard/netlog.pcapng
```

Or directly pipe it into Wireshark:
```
adb exec-out "tcpdump -i any -U -w - 2>/dev/null" | wireshark -k -S -i -
```

### 4. Frida setup
Referring to [Frida docs](https://frida.re/docs/android/).
Download [`frida-server`](https://github.com/frida/frida/releases) for the correct architecture of
your emulated or real device (in my case, `android-arm64`).
```
pip3 install frida-tools
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### 5. Putting it all together

To test to make sure it is working, on host, type:
```
frida-trace -U -i “Java_com_tencent_mm_protocal_*” WeChat
```
Then on the WeChat application, change the application language (this should be possible even
without logging in). This will consistently generate a single MMTLS request. Frida should see a
single call to 
```
Java_com_tencent_mm_protocal_MMProtocalJni_packHybridEcdh()
Java_com_tencent_mm_protocal_MMProtocalJni_unpack()
```
per MMTLS request. You can verify that a single MMTLS request has occurred via Wireshark.

## Collecting keylogs
To collect keylogs, make sure Frida is correctly set up on your device, and `pip` install Frida
bindings for Python:

```
pip install frida-tools
```

Then compile the script in `typescript/` according to the instructions in `typescript/README.md`,
which should compile to `hook_libwechatnetwork.js` in this directory.

Then run `python wechat_multiprocess_hook.py`. Encryption happens *twice* in WeChat, in two
different processes: once in `com.tencent.mm` and once in a subprocess,  `com.tencent.mm:push`. This
script allows us to obtain keys from both processes.

When you collect keylogs, make sure you are capturing network packest via Wireshark, `tcpdump`, etc.
as in Step 3. above.

