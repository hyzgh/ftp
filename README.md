# ftp
A FTP server written in C++.

## Getting started

```
git clone https://github.com/hyzgh/ftp.git
cd ftp
g++ -std=c++11 fs.cpp
sudo ./a.out
```

Under normal circumstances, you could use any ftp clients to connect the server.
I use the built-in ftp client on windows 10, ubuntu 16.04 and ubuntu 18.04 to test, and it worked well.

## Features
Commands that are currently implemented:
- USER
- PASS
- LIST
- RETR
- STOR
- PASV
- PWD
- CWD
- SYST
- PORT
- QUIT



## Todo
Implement more commands.

## Note
Server currently works with linux only.
