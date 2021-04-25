# SigRemover
*Utility to remove digital code signature from binary PE files in Windows.*

### Description

This simple command line tool will remove a [digital code signature](https://en.wikipedia.org/wiki/Code_signing) from PE files in Windows binaries.

It came out as a result of the blog post, "[Coding Production-Style Application - C++ application to remove digital signature from a binary file. Coding it from start-to-finish, with code safety tips, bug fixes and test fuzzing](https://dennisbabkin.com/blog/?t=coding-production-style-cpp-app-to-remove-digital-signature-from-binary-file)". Check it if you're curious how I made this app.

### Release Build

If you don't want to build this app yourself, you can download the latest [release build here](https://dennisbabkin.com/sigremover/).

### Build Instructions

To build this project you will need **Microsoft Visual Studio 2019, Community Edition** with the following installed:

- **Desktop Development with C++** to build `SigRemover` C++ project.
- **.NET Development** to build the `SigRemFuzzer` C# project.



--------------

Submit suggestions & bug reports [here](https://www.dennisbabkin.com/sfb/?what=bug&name=SigRemover&ver=Github).
