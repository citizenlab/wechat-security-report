# Artifact Appendix

Paper title: **What WeChat Knows: Pervasive First-Party Tracking in a Billion-User Super-App Ecosystem**

Artifacts HotCRP Id: **#24**

Requested Badge: **Available**

## Description
This artifact repository provides sample data, code and tooling to analyze and decrypt WeChat's network
transmissions/encryption, and additional documentation of the reverse-engineered  network encryption.
These coincide with the methods described in Section 3, and the results in Section 4.1.

This repository has the following high-level structure.

 * `docs/` has further documentation, RE notes, and pseudocode on the MMTLS format and WeChat network requests in general. In particular, we recommend starting with [this key overview](docs/networking-components/README.md) of WeChat's request sending infrastructure.

 * `data/` contains sample network traffic traces, including decrypted traces.

 * `code/` contains our Frida code, tooling, and setup guides for intercepting and decrypting WeChat traffic on your own device. This contains all the code necessary for running your own experiments as in Section 3, and producing the results described in Section 4.1.

### Security/Privacy Issues and Ethical Concerns (All badges)
To run the Frida scripts and keylog exporting, you will need either a rooted Android device or an
Android emulator. Rooting a mobile device can make it more vulnerable to certain security
issues.

## Environment
The necessary environment to capture and decrypt network traffic is described in [this README
file](code/frida-scripts/README.md). You will need to use an emulated Android device, or a rooted
device.

### Accessibility (All badges)
The artifact can be accessed from the [artifact branch]().

