# FastDPF

A pure C implementation of Distributed Point Functions (DPFs) with several performance optimizations.

## 🚧 WORK IN PROGRSS

### TODOs

- [ ] implement the early termination optimization
- [ ] reduce key size by dropping one correction word
- [ ] fastDPF needs to have final layer hashed for security

Optimizations include:

- Ternary instead of a binary tree (increases communication slightly but improves evaluation performance)
- Using batched AES for fast PRF evaluation with AES-NI
- Full domain evaluation optimization of [Boyle et al.](https://eprint.iacr.org/2018/707)
- The half-tree optimization of [Guo et al.](https://eprint.iacr.org/2022/1431.pdf)

## Dependencies

- OpenSSL 1.1.1f
- GNU Make
- Cmake
- Clang

## Getting everything to run (tested on Ubuntu, CentOS, and MacOS)

| Install dependencies (Ubuntu):         | Install dependencies (CentOS):              |
| -------------------------------------- | ------------------------------------------- |
| `sudo apt-get install build-essential` | `sudo yum groupinstall 'Development Tools'` |
| `sudo apt-get install cmake`           | `sudo yum install cmake`                    |
| `sudo apt install libssl-dev`          | `sudo yum install openssl-devel`            |
| `sudo apt install clang`               | `sudo yum install clang`                    |

### Running tests and benchmarks

```
cd src && make && ./test
```

#### Performance on M1 Macbook Pro

Domain of size $3^{14} \approx 2^{22}$.

```
******************************************
Testing DPF (without half-tree optimization)
DPF full-domain eval time (total) 18.515000 ms
******************************************
Testing Fast DPF (with half-tree optimization)
DPF full-domain eval time (total) 14.641000 ms
******************************************
******************************************
Benchmarking AES
WITHOUT half-tree optimization: time (total) 13.507000 ms
WITH half-tree optimization:    time (total) 9.064000 ms
******************************************
```

## ⚠️ Important Warning

<b>This implementation of is intended for _research purposes only_. The code has NOT been vetted by security experts.
As such, no portion of the code should be used in any real-world or production setting!</b>

## License

Copyright © 2023 Sacha Servan-Schreiber

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
