#!/bin/bash

# install dependencies
sudo apt install -y libssl-dev
sudo apt install -y librust-openssl-dev
sudo apt install -y musl-tools
# windows
sudo apt install -y mingw-w64
# osx
sudo apt install -y cmake
sudo apt install -y libxml2-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# add target and config
rustup target add x86_64-unknown-linux-musl
# windows
rustup target add x86_64-pc-windows-gnu
cat > ~/.cargo/config << EOF
[target.x86_64-pc-windows-gnu]
linker = "/usr/bin/x86_64-w64-mingw32-gcc"
ar = "/usr/x86_64-w64-mingw32/bin/ar"
EOF
# osx
rustup target add x86_64-apple-darwin
cat >> ~/.cargo/config << EOF

[target.x86_64-apple-darwin]
linker = "$HOME/.link/3rdparty/osxcross/target/bin/x86_64-apple-darwin15-clang"
ar = "$HOME/.link/3rdparty/osxcross/target/bin/x86_64-apple-darwin15-ar"
EOF

cargo build --release
echo -e "\n[+] link succesfully built, located at target/release/link"

