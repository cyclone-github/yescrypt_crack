[![Readme Card](https://github-readme-stats-fast.vercel.app/api/pin/?username=cyclone-github&repo=yescrypt_crack&theme=gruvbox)](https://github.com/cyclone-github/yescrypt_crack/)

[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/yescrypt_crack.svg)](https://github.com/cyclone-github/yescrypt_crack/issues)
[![License](https://img.shields.io/github/license/cyclone-github/yescrypt_crack.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/yescrypt_crack.svg)](https://github.com/cyclone-github/yescrypt_crack/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/cyclone-github/yescrypt_crack.svg)](https://pkg.go.dev/github.com/cyclone-github/yescrypt_crack)

### Note: v0.4.0-dev added beta support for OpenCL GPU acceleration.

### Install latest main branch:
```
go install github.com/cyclone-github/yescrypt_crack@main
```

### Info:
I originally wrote this tool in 2025 since yescrypt had become the default /etc/shadow hash for many popular Linux distros such as Debian, Ubuntu, RHEL, Fedora, Arch, etc, and due to the very limited hash cracking tools that supported yescrypt at that time. Now we have several crackers to choose from which all support yescrypt and gost-yescrypt: JtR, yescrypt_crack, mdxfind, and hashcat. 

`yescrypt_crack` supports OpenCL GPU acceleration for yescrypt and gost-yescrypt. GPU mode is used by default when a supported OpenCL GPU is available, and CPU mode is available by using flag `-cpu`. All R&D has been performed on Debian 12/13 Linux. Cross platform support for Windows 10/11 has been implemented and tested. Mac is not supported from v0.4.0 onward, but is supported on v0.3.1. WSL is neither tested or recommended. For best results, Linux is recommended.

`Debian 13 2x RTX 4090`
```
./yescrypt_crack.bin -h hash.txt -w wordlist.txt
 -------------------------------------------------- 
|            Cyclone's Yescrypt Cracker            |
| https://github.com/cyclone-github/yescrypt_crack |
 -------------------------------------------------- 

Hash file:      hash.txt
Total Hashes:   26
CPU Threads:    56
Wordlist:       wordlist.txt
Backend:        auto
GPU selection:  all
GPU batch:      1280
2026/08/20 11:54:25 Counting wordlist lines...
2026/08/20 11:54:25 Tuning GPU...
2026/08/20 11:54:26 OpenCL GPU 0: NVIDIA GeForce RTX 4090, 23.5 GiB VRAM, batch cap 1280, self-test passed
2026/08/20 11:54:26 OpenCL GPU 1: NVIDIA GeForce RTX 4090, 23.5 GiB VRAM, batch cap 1280, self-test passed
2026/08/20 11:54:26 Working...
2026/08/20 11:55:26 Cracked: 0/26  7338.51 H/s	01m:00s/--
2026/08/20 11:56:26 Cracked: 0/26  7391.90 H/s	02m:00s/--
2026/08/20 11:57:26 Cracked: 0/26  7416.85 H/s	03m/1d:17h:06m
2026/08/20 11:58:26 Cracked: 0/26  7434.64 H/s	04m/1d:20h:21m
2026/08/20 11:59:26 Cracked: 0/26  7441.04 H/s	05m/1d:13h:26m
```
`Windows 11 1x RTX 4060`
```
PS C:\Users\cyclone> yescrypt_crack.exe -h hash.txt -w wordlist.txt
 --------------------------------------------------
|            Cyclone's Yescrypt Cracker            |
| https://github.com/cyclone-github/yescrypt_crack |
 --------------------------------------------------

Hash file:      hash.txt
Total Hashes:   1
CPU Threads:    12
Wordlist:       wordlist.txt
Backend:        GPU
GPU selection:  all
GPU batch:      416
2026/08/26 15:22:03 Counting wordlist lines...
2026/08/26 15:22:03 Tuning GPU...
2026/08/26 15:22:03 OpenCL GPU 0: NVIDIA GeForce RTX 4060, 8.0 GiB VRAM, batch cap 416, self-test passed
2026/08/26 15:22:03 Working...
$y$j9T$ss392e/1r/sS364AbKyZU1$Z6lrn5PE2YqIDbgeH590BnPC5fP8BFrkRgOhvo8WKVC:yescrypt_crack
2026/08/26 15:22:04 Cracked: 1/1 3.00 h/s 00m/--
2026/08/26 15:22:04 Finished
```
`Windows 11 Ryzen 5 5500 -cpu`
```
PS C:\Users\cyclone> yescrypt_crack.exe -h hash.txt -w wordlist.txt -cpu
 --------------------------------------------------
|            Cyclone's Yescrypt Cracker            |
| https://github.com/cyclone-github/yescrypt_crack |
 --------------------------------------------------

Hash file:      hash.txt
Total Hashes:   1
CPU Threads:    12
Wordlist:       wordlist.txt
Backend:        CPU
2026/08/26 15:22:49 Counting wordlist lines...
2026/08/26 15:22:49 Working...
$y$j9T$ss392e/1r/sS364AbKyZU1$Z6lrn5PE2YqIDbgeH590BnPC5fP8BFrkRgOhvo8WKVC:yescrypt_crack
2026/08/26 15:22:49 Cracked: 1/1 50.33 h/s 00m/00m
2026/08/26 15:22:49 Finished
```

### Example hash:plain:
```
$y$j9T$ss392e/1r/sS364AbKyZU1$Z6lrn5PE2YqIDbgeH590BnPC5fP8BFrkRgOhvo8WKVC:yescrypt_crack
$gy$j9T$pFEYYB6sbVC37XBX.uMqK/$xY/CaU3ESVzvfR9YErup5kUn2FiHSOoqgAx1zUA99u1:yescrypt_crack
```

### Supported options:
```
-w {wordlist} (omit -w to read from stdin)
-h {yescrypt_hash_file}
-o {output} (omit -o to write to stdout)
-t {cpu threads} (selects CPU mode)
-s {print status every nth sec}
-gpu [all|0,1|list] (default: all GPUs; omit value to use all GPUs)
-cpu (force CPU mode)
-b {gpu batch size} (optional; 0 = auto)

-version (version info)
-help (usage instructions)
```

### Examples:
```
./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -o found.txt

./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -gpu

./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -gpu 0,1

./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -gpu 0,1 -b 1280 -s 10 

./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -cpu -t 16 -s 10

cat wordlist | ./yescrypt_crack.bin -h hashes.txt

./yescrypt_crack.bin -gpu list
```

For backwards compatibility, explicitly specifying `-cpu` selects CPU mode.

### Credits:
* `yescrypt_crack` was written by cyclone in Go
* The yescrypt algorithm was designed by Solar Designer: https://www.openwall.com/yescrypt/
* The CPU yescrypt implementation in `yescrypt_cpu.go` is adapted from `openwall/yescrypt-go`: https://github.com/openwall/yescrypt-go
* The GPU implementation in `yescrypt.cl` is adapted from hashcat's yescrypt OpenCL implementation: https://github.com/hashcat/hashcat/blob/master/OpenCL/inc_hash_yescrypt.cl
* Streebog-256 is provided by `github.com/tarantool/go-gostcrypto/streebog`.
* See `THIRD_PARTY_NOTICES.md` for upstream copyright notices and license terms.

### Changelog:
- https://github.com/cyclone-github/yescrypt_crack/blob/main/CHANGELOG.md

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/yescrypt_crack.git`  # clone repo
  - `cd yescrypt_crack`                                               # enter project directory
  - `go mod tidy`                                                     # download dependencies
  - `go build -ldflags="-s -w" .`                                    # compile binary in current directory
  - `go install -ldflags="-s -w" .`                                  # compile binary and install to $GOPATH
  - `./yescrypt_crack -h {hash file} -w {wordlist file}`             # run yescrypt_crack
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
