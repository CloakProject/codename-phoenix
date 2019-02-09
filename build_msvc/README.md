Building Bitcoin Core with Visual Studio
========================================

Introduction
---------------------
Solution and project files to build the Bitcoin Core applications `msbuild` or Visual Studio can be found in the `build_msvc` directory. The build has been tested with Visual Studio 2017 and 2019.

Building with Visual Studio is an alternative to the Linux based [cross-compiler build](https://github.com/bitcoin/bitcoin/blob/master/doc/build-windows.md).

Quick Start
---------------------
The minimal steps required to build Bitcoin Core with the msbuild toolchain are below. More detailed instructions are contained in the following sections.

```
cd build_msvc
py -3 msvc-autogen.py
msbuild /m bitcoin.sln /p:Platform=x64 /p:Configuration=Release /t:build
```

Dependencies
---------------------
A number of [open source libraries](https://github.com/bitcoin/bitcoin/blob/master/doc/dependencies.md) are required in order to be able to build Bitcoin Core.

Options for installing the dependencies in a Visual Studio compatible manner are:

- Use Microsoft's [vcpkg](https://docs.microsoft.com/en-us/cpp/vcpkg) to download the source packages and build locally. This is the recommended approach.
- Download the source code, build each dependency, add the required include paths, link libraries and binary tools to the Visual Studio project files.
- Use [nuget](https://www.nuget.org/) packages with the understanding that any binary files have been compiled by an untrusted third party.

The [external dependencies](https://github.com/bitcoin/bitcoin/blob/master/doc/dependencies.md) required for building are listed in the `build_msvc/vcpkg.json` file. The `msbuild` project files are configured to automatically install the `vcpkg` dependencies.

Qt
---------------------
In order to build the Bitcoin Core a static build of Qt is required. The runtime library version (e.g. v141, v142) and platform type (x86 or x64) must also match.

Some prebuilt x64 versions of Qt can be downloaded from [here](https://github.com/sipsorcery/qt_win_binary/releases). Please be aware these downloads are NOT officially sanctioned by Bitcoin Core and are provided for developer convenience only. They should NOT be used for builds that will be used in a production environment or with real funds.

To determine which Qt prebuilt version to download open the `.appveyor.yml` file and note the `QT_DOWNLOAD_URL`. When extracting the zip file the destination path must be set to `C:\`. This is due to the way that Qt includes, libraries and tools use internal paths.

To build Bitcoin Core without Qt unload or disable the `bitcoin-qt`, `libbitcoin_qt` and `test_bitcoin-qt` projects.

Building
---------------------
The instructions below use `vcpkg` to install the dependencies.

- Clone `vcpkg` from the [github repository](https://github.com/Microsoft/vcpkg) and install as per the instructions in the main README.md.
- Install the required packages (replace x64 with x86 as required):

```
    PS >.\vcpkg install --triplet x64-windows-static boost-filesystem boost-signals2 boost-test libevent openssl zeromq berkeleydb secp256k1 leveldb
```

- To build from the command line with the Visual Studio 2019 toolchain use:

```
msbuild /m bitcoin.sln /p:Platform=x64 /p:Configuration=Release /t:build
```

- Build in Visual Studio.
