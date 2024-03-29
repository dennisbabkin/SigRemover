# SigRemover
*Utility to remove digital code signature from binary PE files in Windows.*

### Description

This simple command line tool will remove a [digital code signature](https://en.wikipedia.org/wiki/Code_signing) from PE files in Windows binaries.

It came out as a result of the blog post, "[Coding Production-Style Application - C++ application to remove digital signature from a binary file. Coding it from start-to-finish, with code safety tips, bug fixes and test fuzzing](https://dennisbabkin.com/blog/?t=coding-production-style-cpp-app-to-remove-digital-signature-from-binary-file)".


### Screenshot

![scrsht_sigrem_01](https://user-images.githubusercontent.com/25473659/115978721-5bafd880-a536-11eb-8ea8-c6a6868da766.png)


### Release Build

If you don't want to build this app yourself, you can download the latest [release binaries here](https://dennisbabkin.com/sigremover/).

### Build Instructions

To build this project you will need **Microsoft Visual Studio 2019, Community Edition** with the following installed:

- **Desktop Development with C++** to build `SigRemover` C++ project.
- **.NET Development** to build the `SigRemFuzzer` C# project.



--------------

Submit suggestions & bug reports [here](https://www.dennisbabkin.com/sfb/?what=bug&name=SigRemover&ver=Github).
