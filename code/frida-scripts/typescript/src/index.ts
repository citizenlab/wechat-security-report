import { LIBWECHATNETWORK_FUNCTIONS } from './libwechatnetwork_function_map.js';
import { GhidraAddr, GhidraFunction } from './shared.js';
import { SecretStore, HkdfCall, EcdhCall, NamedKey } from './secret_store.js';

const GHIDRA_BASE = 0x00100000;
const MODULE_NAME = "libwechatnetwork.so";
let MODULE_BASE_ADDRESS: NativePointer | null = null;

const SECRET_STORE = new SecretStore();

enum TLogLevel {
    kLevelAll = 0,
    kLevelVerbose = 0,
    kLevelDebug = 1,    // Detailed information on the flow through the system.
    kLevelInfo = 2,     // Interesting runtime events (startup/shutdown), should be conservative and keep to a minimum.
    kLevelWarn = 3,     // Other runtime situations that are undesirable or unexpected, but not necessarily "wrong".
    kLevelError = 4,    // Other runtime errors or unexpected conditions.
    kLevelFatal = 5,    // Severe errors that cause premature termination.
    kLevelNone = 6,     // Special level used to disable all log messages.
}

function getLogLevelString(level: number): string {
    switch (level) {
        case TLogLevel.kLevelAll:
        case TLogLevel.kLevelVerbose:
            return "V";
        case TLogLevel.kLevelDebug:
            return "DEBUG";
        case TLogLevel.kLevelInfo:
            return "INFO";
        case TLogLevel.kLevelWarn:
            return "WARN";
        case TLogLevel.kLevelError:
            return "ERROR";
        case TLogLevel.kLevelFatal:
            return "FATAL";
        case TLogLevel.kLevelNone:
            return "NONE";
        default:
            return `UNKOWN (${level}))`;
    }
}

function printCipherCtx(cipherCtxPtr: NativePointerValue) {
    return hexdump(cipherCtxPtr, {length: 104, ansi: true});
}

function inspectWriteMsgToSendBuffer(this: InvocationContext, args: InvocationArguments) {
    send(`
[+] WriteMsgToSendBuffer
`);
    send(getStackTrace(this));
}

function inspectSend(this: InvocationContext, args: InvocationArguments) {
    send(`
[+] Send
`);
    send(getStackTrace(this));
}

// args: mmtls_client_channel, unknown
function inspectSendHeartbeat(this: InvocationContext, args: InvocationArguments) {
    send(`
[+] SendHeartbeat
 . arg1: ${args[0].readPointer()}
 . arg2: ${args[1].readPointer()}
`);
    send(getStackTrace(this));
}

function getFunctionByAddr(address: GhidraAddr): GhidraFunction | null {
    for (const fn of LIBWECHATNETWORK_FUNCTIONS) {
        if (address >= fn.start && address <= fn.end) {
            return fn;
        }
    }
    return null;
}

function getStackTrace(inv: InvocationContext): string {
    return Thread.backtrace(inv.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map((sym) => {
            const [_, libfn] = sym.toString().split(" ");
            const [lib, fnAddr] = libfn.split("!");
            if (lib === 'libwechatnetwork.so') {
                let addr = parseInt(fnAddr, 16);
                addr += GHIDRA_BASE;
                let addrStr = addr.toString(16);
                addrStr = "0x" + "0".repeat(8 - addrStr.length) + addrStr;
                let ghidraFn = getFunctionByAddr(addr);
                if (ghidraFn) {
                    return `${lib}!${ghidraFn.name}+${addrStr}`;
                } else {
                    return `${lib}!${addrStr}`;
                }
            } else {
                return libfn;
            }
        })
        .join("\n");
}

function ghidraToReal(addr: NativePointer): NativePointer {
    return addr.sub(GHIDRA_BASE).add(MODULE_BASE_ADDRESS!);
}

function realToGhidra(addr: NativePointer): NativePointer {
    return addr.add(GHIDRA_BASE).sub(MODULE_BASE_ADDRESS!);
}

function getCallerGhidraAddr(inv: InvocationContext): string {
    let caller = Thread.backtrace(inv.context, Backtracer.ACCURATE)[2];
    let callerGhidra = realToGhidra(caller).toUInt32();
    if (callerGhidra == 0x2293b0) { // This seems to be some XLogger convenience function, go one caller up
        caller = Thread.backtrace(inv.context, Backtracer.ACCURATE)[3];
        callerGhidra = realToGhidra(caller).toUInt32();
    }
    const fnName = getFunctionByAddr(callerGhidra)?.name ?? "unknown";
    return `${fnName}+0x${callerGhidra.toString(16)}`;
}

function incrementNonce(nonce: ArrayBuffer) {
    const bytes = new Uint8Array(nonce, 0);
    let carry = 1;
    for (let i=0; i<bytes.length; i++) {
        if (!carry) {
            continue;
        }
        if (bytes[bytes.length - i - 1] === 255) {
            bytes[bytes.length - i - 1] = 0;
        } else {
            carry = 0;
            bytes[bytes.length - i - 1]++;
        }
    }
}

const byteToHex: string[] = [];

for (let n = 0; n <= 0xff; ++n)
{
      const hexOctet: string = n.toString(16).padStart(2, "0");
      byteToHex.push(hexOctet);
}

function hex(arrayBuffer: ArrayBuffer): string
{
      return Array.prototype.map.call(
              new Uint8Array(arrayBuffer),
              n => byteToHex[n]).join("");
}

// FUN_002298c8_Crypt(cipher_ctx *ctx,ulong nonce,ulong nonce_len,long input,ulong inputlen,
//                    ulong input_str,ulong input_str_len,astruct_9 *output)
function cryptOnEnter(this: InvocationContext, args: InvocationArguments) {
    const encrypt = args[0].add(0x20).readU8() !== 0;
    this.encryptOrDecrypt = encrypt ? 'ENCRYPT' : 'DECRYPT';
    const noncePtr = args[1];
    const nonceLen = args[2].toUInt32();
    const nonce = args[1].readByteArray(nonceLen)!;
    const keyPtr = args[0].add(0x50).readPointer();
    const keyLen = args[0].add(0x10).readU32();
    const key = keyPtr.readByteArray(keyLen)!;
    // const hkdfResult = SECRET_STORE.findMatch(key);
    const firstInputLength = args[4].toUInt32();
    const firstInput = args[3].readByteArray(firstInputLength)!;

    this.cryptKey = {
      layer: "OUTER",
      encrypt: encrypt,
      nonce: hex(nonce),
      key: hex(key),
      metadata: hex(firstInput),
    };
    // If we're decrypting, the input is the ciphertext.
    if (!this.cryptKey.encrypt) {
      const secondInputLength = args[6].toUInt32();
      const last8Bytes = args[5].add(secondInputLength - 8).readByteArray(8)!;
      this.cryptKey["tail"] = hex(last8Bytes);
      send(JSON.stringify(this.cryptKey));
    }
    this.output = args[7];
}

function cryptOnLeave(this: InvocationContext, retval: InvocationReturnValue) {
  const outputPtr: NativePointer = this.output;
  if (this.cryptKey.encrypt) {
    const ciphertextPtr = outputPtr.add(0x8).readPointer();
    const ciphertextLen = outputPtr.add(0x10).readU32();
    const last8Bytes = ciphertextPtr.add(ciphertextLen - 8).readByteArray(8)!;
    this.cryptKey["tail"] = hex(last8Bytes);
    send(JSON.stringify(this.cryptKey));
  }
}



interface TargetFunc {
    addr: GhidraAddr;
    name: string;
    cb: ScriptInvocationListenerCallbacks;
    numArgs?: number;
}

type EnterCallback = (this: InvocationContext, args: InvocationArguments) => void;
type LeaveCallback = (this: InvocationContext, retval: InvocationReturnValue) => void;

function target(addr: GhidraAddr, name: string, numArgs?: number, onEnter?: EnterCallback, onLeave?: LeaveCallback): TargetFunc {
    return {
        addr,
        name,
        cb: {
            onEnter,
            onLeave,
        },
        numArgs,
    };
}

function overrideReturnValue(value: number | string): LeaveCallback {
    return function (this: InvocationContext, retval: InvocationReturnValue) {
        retval.replace(ptr(value));
    }
}

function inspectXloggerWrite(this: InvocationContext, args: InvocationArguments) {
    if ('x0' in this.context) {
        const xloggerInfoPtr = this.context.x0; // `this` on arm64 lives in the x0 register
        const logLevel = getLogLevelString(xloggerInfoPtr.readU8());
        const tag = xloggerInfoPtr.add(0x8).readPointer().readCString();
        const filename = xloggerInfoPtr.add(0x10).readPointer().readCString();
        const abdridgedFilename = filename?.split('/')?.slice(6).join('/');
        const funcname = xloggerInfoPtr.add(0x18).readPointer().readCString();
        const caller = getCallerGhidraAddr(this);
        send(`[XLog] [${logLevel}] ${tag} - ${abdridgedFilename}:${funcname} (${caller})\n${args[1].readCString()}`);
    } else {
        throw new Error(`not an arm64 context`);
    }
}

function computeResumptionSecretOnEnter(this: InvocationContext, args: InvocationArguments) {
    this.out = args[2];
}

function computeResumptionSecretOnLeave(this: InvocationContext, reval: InvocationReturnValue) {
    const resultPtr = this.out.add(0x08).readPointer();
    const resultLen = this.out.add(0x10).readU32();
    send(`[+] ComputeResumptionSecret done

expanded:
${hexdump(resultPtr, { length: resultLen })}

stack trace:
${getStackTrace(this)}
`)
}

function hkdfExpandOnEnter(this: InvocationContext, args: InvocationArguments) {
    const resultLen = args[5].toUInt32();
    const secretLen = args[2].toUInt32();
    const secret = args[1].readByteArray(secretLen)!;
    const secretStoreResult = SECRET_STORE.findMatch(secret);
    let labelLen = args[4].toUInt32();
    if (labelLen > 32) {
        labelLen -= 32; // dunno why it's off by 32 sometimes
    }
    const label = args[3].readCString(labelLen)!;
    this.hkdfCall = new HkdfCall(resultLen, label, secret);
    this.out = args[6];
    send(`[+] HKDF_Expand call start
    
secret (${secretStoreResult === null ? 'UNKNOWN' : secretStoreResult.name()}):
${hexdump(args[1], { length: secretLen })}

source of secret:
${secretStoreResult === null ? 'UNKNOWN' : secretStoreResult}

label:
${hexdump(args[3], { length: labelLen })}

expansion length: ${resultLen}

stack trace:
${getStackTrace(this)}
`);
}

function hkdfExpandOnLeave(this: InvocationContext, reval: InvocationReturnValue) {
    const resultPtr = this.out.add(0x08).readPointer();
    const resultLen = this.out.add(0x10).readU32();
    this.hkdfCall.result = resultPtr.readByteArray(resultLen)!;
    const secretName = SECRET_STORE.add(this.hkdfCall);
    send(`[+] HKDF_Expand done, created ${secretName}

expanded master key:
${hexdump(resultPtr, { length: resultLen })}`)
}

function noop(this: InvocationContext, args: InvocationArguments) {}

function computeMasterSecretOnEnter(this: InvocationContext, args: InvocationArguments) {
    const hkdfExpandSecretFn = args[0].add(0xe8).readPointer().add(0x18);
    const hkdfExtractMasterSecretFn = realToGhidra(args[0].add(0xe8).readPointer().add(0x10));
    const finalFn = realToGhidra(args[0].add(0x128).readPointer().add(0x10));
    send(`[+] ComputeMasterSecret

hkdfExpandSecretFn: ${hkdfExpandSecretFn}
hkdfExtractMasterSecretFn: ${hkdfExtractMasterSecretFn}
finalFn: ${finalFn} 

crypto_util:
${hexdump(args[0], { length: 572 })}`)
}

function ecdhOnEnter(this: InvocationContext, args: InvocationArguments) {
    this.out = args[6]
    const pubPtr = args[2];
    const pubLen = args[3].toUInt32();
    const pub = args[2].readByteArray(pubLen)!;
    const privPtr = args[4];
    const privLen = args[5].toUInt32();
    const priv = args[4].readByteArray(privLen)!;
    this.ecdhCall = new EcdhCall(pub, priv);

    // right now i'm reasonably sure that all calls to ECDH are w/ server public
    // and client private keys. this could change in a logged-in case
    const pubSecretName = SECRET_STORE.add(new NamedKey(pub, 'server_pub'));
    const prvSecretName = SECRET_STORE.add(new NamedKey(priv, 'client_priv'));

    send(`[+] CryptoUtil_ECDH call start

nid:
${args[1].toUInt32()}

pub (named ${pubSecretName}):
${hexdump(pubPtr, { length: pubLen })}

priv (named ${prvSecretName}):
${hexdump(privPtr, { length: privLen })}

stacktrace:
${getStackTrace(this)}
`)
}

function ecdhOnLeave(this: InvocationContext, reval: InvocationReturnValue) {
    const outPtr = this.out.add(0x8).readPointer();
    const outLen = 0x20; // SHA256 output is always 32 bytes
    const outBuf = outPtr.readByteArray(outLen)!;
    this.ecdhCall.result = outBuf;
    const secretName = SECRET_STORE.add(this.ecdhCall);
    send(`[+] CryptoUtil_ECDH Done, created ${secretName}

out:
${hexdump(outPtr, { length: outLen })}`)
}

function secretMysteryFnOnEnter(this: InvocationContext, args: InvocationArguments) {
    this.arg = args[0]
    send(`[+] SecretMysteryFn

arg1:
${hexdump(this.arg)}

stacktrace:
${getStackTrace(this)}
`)
}

function secretMysteryFnOnExit(this: InvocationContext, reval: InvocationReturnValue) {
    send(`[+] SecretMysteryFn Done

arg1:
${hexdump(this.arg)}`)
}


const TARGET_FUNCS: TargetFunc[] = [
    //target(0x2298c8, "Crypt", 8, cryptOnEnter, cryptOnLeave),
    target(0x22ae10, "Crypt", 8, cryptOnEnter, cryptOnLeave),
    ////target(0x219b28, "MMTLS_SendHeartbeat", inspectSendHeartbeat),
    ////target(0x22c324, "ClientChannel_WriteMsgToSendBuffer", inspectWriteMsgToSendBuffer),
    ////target(0x2198c0, "ClientChannel_Send", inspectSend),
    ////target(0x245e38, "MMTLSRecordReader_DecryptRecord", decryptRecordOnEnter),
    //target(0x3e5814, "XLogger_IsEnabledFor", undefined, noop, overrideReturnValue(1)),
    //target(0x3e5870, "XLogger_Write", undefined, inspectXloggerWrite),
    //target(0x229258, "XLogger_CheckLogLevel", undefined, noop, overrideReturnValue(0)),
    ////target(0x225830, "ClientCredentialStorage_SavePsk", 2),

    //target(0x225830, "ClientCredentialStorage_SavePsk", 2),
    //// Handshake stages
    //target(0x21fa68, "🤝CreateClientHello", 0),
    //target(0x21c4f0, "🤝HandshakeLoop_ClientHello", 0),
    //target(0x21c7e0, "🤝HandshakeLoop_SendEncryptedExtensions", 0),
    //target(0x21ca1c, "🤝HandshakeLoop_DoSendEarlyAppData", 0),
    //target(0x21cca0, "🤝HandshakeLoop_DoReceiveServerHello", 0),
    //target(0x21cfc8, "🤝HandshakeLoop_DoReceiveCertificateVerify", 0),
    //target(0x21e1cc, "🤝HandshakeLoop_DoReceiveNewSessionTicket", 0),
    //target(0x21e3d0, "🤝HandshakeLoop_DoReceiveServerFinished", 0),
    ////target(0x23e064, "🤝HandshakeLoop_ProcessReceivedEarlyAppData", 0),
    //target(0x21e698, "🤝HandshakeLoop_SendClientFinished", 0),
    ////FUN_002d5e00__OnSend (longlink)
    ////FUN_002baf70_Send
    //target(0x21e698, "🐍LL_Send", 0),
    //target(0x219dfc, "🐍LL_Receive", 0),


    //target(0x225a7c, "ClientCredentialStorage_SaveRefreshPskToFile", 1),
    //target(0x226fcc, "ClientCredentialStorage_LoadRefreshPskFromFile", 1),
    ////target(0x23d89c, "ComputeResumptionSecret", 3, computeResumptionSecretOnEnter, computeResumptionSecretOnLeave),
    //target(0x23bd2c, "ComputeMasterSecret", 1),
    //target(0x2416b4, "HkdfExtract", 6),
    //target(0x241938, "HkdfExpand", 7, hkdfExpandOnEnter, hkdfExpandOnLeave),
    //target(0x242628, "HkdfDeriveKey", 9),
    //target(0x23c9d8, "Handshake_ComputeStageConnKey", 4),
    ////target(0x22c4e0, "MMTLSChannel_ComputeStageConnCipherState", 5),
    ////target(0x247998, "SecretMysteryFn", 1, secretMysteryFnOnEnter, secretMysteryFnOnExit),
    //target(0x242aec, "CryptoUtil_ECDH", 7, ecdhOnEnter, ecdhOnLeave),
    //target(0x2b383c, "OtherCryptoUtil_ECDH", 7), // seemingly not called?
    //target(0x226a44, "GetEcdhStaticKey", 1),
    //target(0x3c0a68, "Protobuf_CodedStream_Read?", 1),
    //target(0x3c1de8, "Protobuf_MessageLite_Parse?", 3),
    //target(0x3c2494, "ProtobufCheckVersion?", 3),

    // FUN_002adad4_Encrypt ax_ecdh_client.cc
    // FUN_002b7074_Encrypt hybrid_ecdh_client.cc
];

function hookFuncs() {
    var module = Process.findModuleByName(MODULE_NAME);
    if (module == null) {
        send("module was null, waiting and trying again...");
        setTimeout(hookFuncs, 1000);
        return;
    }

    send("[+] Module found: " + MODULE_NAME);
    MODULE_BASE_ADDRESS = Module.findBaseAddress(MODULE_NAME)!;

    TARGET_FUNCS.map(({name, addr: ghidraAddr, cb, numArgs}) => {
        const realAddr = MODULE_BASE_ADDRESS!.add(ghidraAddr - GHIDRA_BASE);
        if (cb.onEnter === undefined) {
            cb.onEnter = function (this: InvocationContext, args: InvocationArguments) {
                let argInfo = '';
                if (numArgs !== undefined) {
                    for (let i=0; i<numArgs; i++) {
                        try {
                            argInfo += `arg${i+1}:\n${hexdump(args[i])}\n\n`;
                        } catch (e) {
                            argInfo += `arg${i+1} (ERR):\n${e}\n\n`
                        }
                    }
                }
                send(`[!] Called ${name}
${argInfo}
stack trace:
${getStackTrace(this)}`);
            };
        } else {
            const userOnEnter = cb.onEnter;
            cb.onEnter = function(this: InvocationContext, args: InvocationArguments) {
                this.numArgs = numArgs;
                userOnEnter.call(this, args);
            }
        }
        Interceptor.attach(realAddr, cb);
        send('[+] Hooked '+name+ " at " + realAddr);
    });
}

Interceptor.attach(Module.findExportByName(null, "open")!, {
    onEnter: function (args) {
        var arg = args[0].readUtf8String()!;
        if (arg.includes(MODULE_NAME)) {
            setTimeout(hookFuncs, 500);
        }
    },
});
