[![Build status](https://ci.appveyor.com/api/projects/status/3yludsnwm5a1jnsa/branch/master?svg=true)](https://ci.appveyor.com/project/Antidote1911/dexiosgui/branch/master)
[![Cargo Build](https://github.com/Antidote1911/dexiosgui/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Antidote1911/dexiosgui/actions/workflows/ci.yml)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)


# DexiosGUI
**Simple cross-platform drag-and-drop Dexios file encryption.**<br/>
Latest Windows x64 release is [here](https://github.com/Antidote1911/dexiosgui/releases/latest).

DexiosGUI is a Qt/C++ app for encrypt and decrypt files with the [Dexios format](https://github.com/brxken128/dexios-core) made by [ brxken128](https://github.com/brxken128).

This app is a work in progress made in 3 hours ! Sorry for english typo, comments ect... I don't have much time. It use modifications of my encryption tool [Cryptyrust](https://github.com/Antidote1911/cryptyrust) to use Dexios format.

For a full CLI application, have a look to [Dexios](https://github.com/brxken128/dexios).

![Demo](demo.gif)  
The gif demo is Cryptyrust, but Dexiosgui is similar.

## Technical details:
For now, DexiosGUI include Dexios-core Git crate in this project for some reasons:
- Test the latest encryption format before it was released.
- Make a little modification of the encryption/decryption loop to return the progress percentage. (Add this in the future release of the crate can be interesting for have a progress in cli or gui application.)
- Add the constant "CORE_VERSION" to display the Dexios-core version in the DexiosGUI about window.

DexiosGUI must be considered as Alpha and not be used as a production application. Please be patient !

Suggestion: DexiosGUI detect if the input file is a dexios encrypted file by ckecking the firsts 2 bytes.
`[0xDE, 0x01]`, `[0xDE, 0x02]` or `[0xDE, 0x03]` respectively Header version 1,2 and 3.  
Checking only 2 Bytes is to short and some files can be wrongly identified by DexiosGUI (or OS) as Dexios files. I think the Dexios-core crate need to introduce a classic 4 bytes Magic Number in future major release.

## Build Linux core instructions:
In the root folder build the rust core lib with `cargo build --release`

## Build Windows core instructions:

- Install [Visual Studio Build Tools 2019](https://visualstudio.microsoft.com/fr/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16)  
- Make sure rust use msvc. Run in command line :
`rustup default stable-x86_64-pc-windows-msvc`
- Build rust core project : `cargo build --release`

## C++ GUI Compilation instructions:
C++ GUI require Qt5 or Qt6 and rust core build with `cargo build --release`.
After building the Rust core, Open qtgui/CMakeLists.txt with your IDE and build it. If You use qt creator, you can open project dexiosgui.pro to build it.


```bash
# With Linux command-line, open a terminal in qtgui folder
qmake dexiosgui.pro
make
```
```bash
# For Windows
cd qtgui
mkdir build
cd build
cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ..
nmake
```
**Data Loss Disclaimer:**  
if you lose or forget your password, **your data cannot be recovered !**  
Use a password manager or another secure form of backup.<br/>
