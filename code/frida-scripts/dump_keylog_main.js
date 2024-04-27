const GHIDRA_BASE = 0x00100000;
const MODULE_JNI_NAME = "libMMProtocalJni.so";
const MODULE_MM_NAME = "libwechatmm.so";

const byteToHex = [];

for (let n = 0; n <= 0xff; ++n)
{
      const hexOctet = n.toString(16).padStart(2, "0");
      byteToHex.push(hexOctet);
}

function hex(arrayBuffer)
{
      return Array.prototype.map.call(
              new Uint8Array(arrayBuffer),
              n => byteToHex[n]).join("");
}

function AesCbcEncryptEnter(args) {
  const key = args[0].readByteArray(16);
  this.cryptKey = {
    layer: "INNER",
    encrypt: true,
    key: hex(key),
    nonce: hex(key),
  }
  this.outPtr = args[6];
  this.outLPtr = args[7];
}

function AesCbcEncryptLeave(args) {
  const outLen = this.outLPtr.readPointer().toUInt32();
  const last8Bytes = this.outPtr.readPointer().add(outLen - 8).readByteArray(8);
  this.cryptKey["tail"] = hex(last8Bytes);
  console.log(JSON.stringify(this.cryptKey));
}

function AesCbcDecryptEnter(args) {
  const key = args[0].readByteArray(16);
  const len = args[5].toUInt32();
  this.cryptKey = {
    layer: "INNER",
    encrypt: false,
    key: hex(key),
    nonce: hex(key),
    tail: hex(args[4].add(len-8).readByteArray(8)),
  }
  console.log(JSON.stringify(this.cryptKey));
}

function AesGcmEncryptEnter(args) {
  const iv = args[1].readByteArray(args[2].toUInt32());
  const key = args[3].readByteArray(24);
  const aad = args[5].readByteArray(args[6].toUInt32());
  this.cryptKey = {
    layer: "INNER",
    encrypt: true,
    key: hex(key),
    iv: hex(iv),
    metadata: hex(aad),
    tail: hex(iv),
  }
  this.outPtr = args[9];
  this.outLen = args[8].toUInt32();
  this.tagPtr = args[10];
  this.tagPtrLen = args[11].toUInt32();
}

function AesGcmEncryptLeave(args) {
  this.cryptKey["tag"] = hex(this.tagPtr.readByteArray(this.tagPtrLen));
  console.log(JSON.stringify(this.cryptKey));
}


function AesGcmDecryptEnter(args) {
  const iv = args[1].readByteArray(args[2].toUInt32());
  const key = args[3].readByteArray(args[4].toUInt32());
  let aad = "";
  if (args[5].toUInt32() === 0) {
    aad = "";
  } else {
    aad = args[5].readByteArray(args[6].toUInt32());
  }
  const ctLen = args[8].toUInt32();
  const tail = args[7].add(ctLen - 8).readByteArray(8);
  // console.log(hexdump(args[7], {length: ctLen}));
  const tag = args[9].readByteArray(args[10].toUInt32());
  this.cryptKey = {
    layer: "INNER",
    encrypt: false,
    key: hex(key),
    iv: hex(iv),
    metadata: hex(aad),
    tail: hex(tail),
    tag: hex(tag),
  }
  console.log(JSON.stringify(this.cryptKey));
}




// offsets from 8023 / 2160 version. link:
// https://dldir1.qq.com/weixin/android/weixin8023android2160_arm64_1.apk
var target_funcs = {
  "libMMProtocalJni.so": [
     //{addr: 0x0013d108, name: "AesCbcEncrypt", onEnterFn: AesCbcEncryptEnter, onLeaveFn: AesCbcEncryptLeave},
     //{addr: 0x0013d294, name: "AesCbcDecrypt", onEnterFn: AesCbcDecryptEnter},
     {addr: 0x0013d6b0, name: "AesCbcEncrypt", onEnterFn: AesCbcEncryptEnter, onLeaveFn: AesCbcEncryptLeave},
     {addr: 0x0013d83c, name: "AesCbcDecrypt", onEnterFn: AesCbcDecryptEnter},
  ],
  "libwechatmm.so": [
     //{addr: 0x001e5210, name: "AesGcmEncrypt", onEnterFn: AesGcmEncryptEnter, onLeaveFn: AesGcmEncryptLeave},
     //{addr: 0x001e4c78, name: "AesGcmDecrypt", onEnterFn: AesGcmDecryptEnter},
     {addr: 0x001d7ea4, name: "AesGcmEncrypt", onEnterFn: AesGcmEncryptEnter, onLeaveFn: AesGcmEncryptLeave},
     {addr: 0x001d780c, name: "AesGcmDecrypt", onEnterFn: AesGcmDecryptEnter},
  ]
};

function hookFuncs(module_name) {
    var module = Process.findModuleByName(module_name);
    if (module == null) {
        console.log("module was null");
        return;
    }
    console.log("[+] Module found: " + module_name);
    var moduleBaseAddress = Module.findBaseAddress(module_name);

    let func_hooks = target_funcs[module_name];
    func_hooks.map( ({name, addr, onEnterFn, onLeaveFn}) => {
        const realAddr = moduleBaseAddress.add(addr - GHIDRA_BASE);
        if (onEnterFn == null) {
            onEnterFn = (args) => console.log('[!] Called ' + name);
        }
        Interceptor.attach(realAddr, {
            onEnter: onEnterFn,
            onLeave: onLeaveFn,
        });
        console.log('[+] Hooked '+name+ " at " + realAddr);
    });
}

Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function (args) {
        var arg = args[0].readUtf8String();
        if (arg.includes(MODULE_JNI_NAME)) {
            setTimeout(() => hookFuncs(MODULE_JNI_NAME), 100);
        }
        if (arg.includes(MODULE_MM_NAME)) {
            setTimeout(() => hookFuncs(MODULE_MM_NAME), 100);
        }
    },
});

