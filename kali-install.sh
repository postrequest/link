#!/bin/bash

# install dependencies
sudo apt install -y mingw-w64
sudo apt install -y libssl-dev
sudo apt install -y librust-openssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# pr
rustup target add x86_64-pc-windows-gnu
cat > ~/.cargo/config << EOF
[target.x86_64-pc-windows-gnu]
linker = "/usr/bin/x86_64-w64-mingw32-gcc"
ar = "/usr/x86_64-w64-mingw32/bin/ar"
EOF

cargo build --release
echo -e "\n[+] link succesfully built, located at target/release/link"

