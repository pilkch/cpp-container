## About

This is a C++ rewrite of Lizzie Dixon's excellent C container here:  
https://blog.lizzie.io/linux-containers-in-500-loc.html

This version simplifies and cleans up the code a bit.  Still approximately 600 lines of code, but easier to read.  Now with no gotos!  
It would be interesting to extract the container code into a library, then you could create a container in something like 10 lines.  But at that point you would basically just have a less featured, less secure version of libcontainer.

**NOTE: This is just a proof of concept**
- **It doesn't have basic, nice things like networking, package management, file system overlays, any sort of Dockerfile/makefile/recipe support, code reviews, testing, battle hardened development history, etc.**
- **It's not Docker, it's a proof of concept of the basics of how containers work that doesn't hide everything away in Python/Go or libraries.**
- **It runs as root**
- **It modifies files as root, just one directory below other important system files, use at your own risk!**

## Building

Install dependencies:
```bash
sudo apt install libcap-dev libseccomp-dev
```
OR
```bash
sudo dnf install libcap-devel libseccomp-devel
```

Build cpp-container:
```bash
cmake .
make
```

## Running

Extract busybox:
```bash
BUSYBOX_VERSION=1.33.0
(mkdir busybox-${BUSYBOX_VERSION} && cp busybox-${BUSYBOX_VERSION}.tar.xz ./busybox-${BUSYBOX_VERSION} && cd busybox-${BUSYBOX_VERSION} && tar -xf busybox-${BUSYBOX_VERSION}.tar.xz && rm busybox-${BUSYBOX_VERSION}.tar.xz)
```

Run /bin/sh in a container:
```bash
sudo ./cpp-container -h myhostname -m $(realpath ./busybox-${BUSYBOX_VERSION}/) -u 0 -c /bin/sh
```

Which user are we running as in the container?
```bash
/ # whoami
root
```

If we run pstree on the host we have this structure:  
bash───sudo───cpp-container───sh

On the host:
```bash
$ cat
<expecting input>
```

The above cat process has a pid of 265314.  Trying to kill it from the container fails:
```bash
/ # kill 265314
sh: can't kill pid 265314: No such process
```
