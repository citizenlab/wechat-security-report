This repository contains utility tools for decrypting, testing, and understanding WeChat's network encryption.

## Collecting keylogs

Follow the setup guide in `frida-scripts/README.md` to run the Frida scripts for exporting keys.

## Decrypting keylogs

`decrypt-keylog.py` performs decryption, and `decode-requests.py` opportunistically decompresses and
decodes protobuf data from each request.

Example against simple network capture of simply opening WeChat:
```
pip install requirements.txt
python decrypt-keylog.py ../data/frida-logged-in-all-keys.log
../data/capture-logged-in-all-keys.pcapng | python decode-requests.py
```

