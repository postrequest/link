<h1 align="center"> link </h1> <br>
<p align="center">
  <a href="https://github.com/postrequest/link">
    <img alt="🔗" title="link" src="https://i.giphy.com/6d2rN7dGii0eiKB2HO.gif" width="450">
  </a>
</p>

<p align="center">
  link is a command and control framework written in rust. Currently in <strong>alpha</strong>.
</p>

<p align="center">
  <a href="https://www.youtube.com/watch/dQw4w9WgXcQ">
    <img alt="Download on the App Store" title="App Store" src="http://i.imgur.com/0n2zqHD.png" width="140">
  </a>

  <a href="https://www.youtube.com/watch/dQw4w9WgXcQ">
    <img alt="Get it on Google Play" title="Google Play" src="http://i.imgur.com/mtGRPuM.png" width="140">
  </a>
</p>

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Feedback](#feedback)
- [Build Process](#build-process)
- [Acknowledgments](#acknowledgments)

## Introduction

[![Repo Size](https://img.shields.io/github/repo-size/postrequest/link)](https://img.shields.io/github/repo-size/postrequest/link)
[![Lines of code](https://img.shields.io/tokei/lines/github/postrequest/link)](https://img.shields.io/tokei/lines/github/postrequest/link)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.en.html)

At this stage of development, link provides a Windows implant only which lacks evasive tradecraft provided by other more mature command and control frameworks.

**Tested on Linux only.**

## Features

Hopefully this list expands for humans to actually want to use this:

* HTTPS communication
* Process injection
* In-memory .NET assembly execution
* SharpCollection tools
* sRDI implementation for shellcode generation

## Feedback

link is currently not even in __beta__, but fo feel free to [file an issue](https://github.com/postrequest/link/issues/new).

## Build Process

- Clone or download the repo
- `cargo run` if you are eager to run it **right now**
- `cargo build --release` to build the link server executable

For more information checkout [Installation and Usage](https://github.com/postrequest/link/wiki/Installation-and-Usage).

## Acknowledgments

A non-exhaustive list of those who have in some way inspired this project by means of writing code, snippets, ideas or inspiration:

[@rust](https://github.com/rust-lang)  
[@moloch--](https://github.com/moloch--)  
[@djhohnstein](https://github.com/djhohnstein)  
[@lesnuages](https://github.com/lesnuages)  
[@Flangvik](https://github.com/Flangvik)  
[@monoxgas](https://github.com/monoxgas)  

