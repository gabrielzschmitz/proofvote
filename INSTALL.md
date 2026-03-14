# ProofVote

## Requirements
- C++17 compiler
- Premake5
- OpenSSL

---

## Install dependencies

### Linux
```bash
sudo apt install g++ make pkg-config libssl-dev premake4
sudo pacman -S base-devel openssl premake
````

### macOS

```bash
brew install openssl pkg-config premake
```

### Windows

* Install Premake: [https://premake.github.io/](https://premake.github.io/)
* Install OpenSSL: [https://www.openssl.org/](https://www.openssl.org/)
* Default path: `C:\OpenSSL-Win64`

---

## Build

```bash
premake5 gmake2
make config=release_x64
```

---

## Run

```bash
./bin/realease_x64/leader_node
./bin/realease_x64/client_node
```

---

## Clean

```bash
make clean
```
