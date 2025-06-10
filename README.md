WeChat MMTLS Documentation
===

This repository contains additional data, documentation, and tooling from our reverse-engineering of
WeChat's network protocol. Related publications:

 * What WeChat Knows: Pervasive First-Party Tracking in a Billion-User Super-App Ecosystem (PETS 2025)
 * [Security analysis of WeChat's MMTLS](https://citizenlab.ca/2024/10/should-we-chat-too-security-analysis-of-wechats-mmtls-encryption-protocol/) (2024)
 * [Privacy in the WeChat Ecosystem](https://citizenlab.ca/2023/06/privacy-in-the-wechat-ecosystem-full-report/) (2023)

Subdirectories
===

`docs/` has further documentation, RE notes, and pseudocode on the MMTLS format and WeChat network requests in general. In particular, we recommend starting with [this key overview](docs/networking-components/README.md) of WeChat's request sending infrastructure.

`data/` contains sample network traffic traces, including decrypted traces.

`code/` contains our Frida code, tooling, and setup guides for intercepting and decrypting WeChat traffic on your own device.

