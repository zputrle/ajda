#  <img src="./imgs/logo.svg" width="30">  [Ajda](https://github.com/zputrle/ajda)

**Ajda** is a reasonably secure minimal HTTPS server that:

- is **simple** and **easy to review**,
- is written in **Go** as a **single file**,
- is **secure by default**,
- serves only **a predefined set of files** and
- runs on **Linux**, for example, Debian.

Perfect for self-hosting a blog. Just generate a static webpage and serve it with Ajda.

See [Code](https://github.com/zputrle/ajda/blob/main/src/ajda.go) / [GitHub](https://github.com/zputrle/ajda).

## How to run

Run
```bash
go run src/ajda.go --rootDirPath ./pages --address :8080 --home ajda.html \
    --server_cert cert/server.crt --server_key cert/server.key 
```

Expected output:
```
2026/11/05 11:33:06 INFO Starting ... serving_files_from=./pages
2026/11/05 11:33:06 INFO Serving file. path=/ajda.html
2026/11/05 11:33:06 INFO Serving file. path=/robots.txt
2026/11/05 11:33:06 INFO Serving file. path=/src/lnew.css
2026/11/05 11:33:06 INFO Serving file. path=/src/theme.css
2026/11/05 11:33:06 INFO Limiting the number of cores and memory. #cores=1 memory(MB)=512
2026/11/05 11:33:06 INFO Whitelisting system calls. system_calls="write, epoll_ctl, accept4, epoll_pwait, futex, read, getsockname, getrandom, lseek, rt_sigprocmask, tgkill, rt_sigreturn, rt_sigaction, close, clone3, mmap, mprotect, set_robust_list, rseq, nanosleep, munmap, sigaltstack, exit_group"
2026/11/05 11:33:06 INFO Listening ... on_address=:8080
```

Use `--help` for all the options:
```bash
go run src/ajda.go --help
```

## Security

The goal behind Ajda is to provide a simple way to self-host a blog on a Raspberry Pi in a secure way. To that end, Ajda is built to **(I)** be as simple as possible, **(II)** serve only a predefined set of files, and **(III)** prevent compromise of the underlying system.

Ajda is built around the idea that **programs should limit what they can do at startup in order to minimize the attack surface if they are compromised**. For example, programs should always limit which system calls they can make and which files they can access. As a result, even if a program is compromised, an attacker cannot make arbitrary system calls or interact with arbitrary files.

**(I) Simplicity:** Ajda is simple by design, uses Go's well-maintained standard library (Footnote 1), and is contained in a single file. This makes Ajda easy to understand and audit.

**(II) Serve only selected files**: Ajda serves only files that are present in the _root directory_ at startup. When Ajda starts, it goes through the root directory and opens all the files in read mode, obtaining a file descriptor for each. It then drops the privilege to open any further files through [seccomp](https://lwn.net/Articles/656307/). The descriptors are then used to serve files when Ajda receives a request (Footnote 2), never needing to open a file again. The files that are served are logged at startup after they are opened.
```
2026/06/07 16:28:24 INFO Serving file. path=/ajda.html
2026/06/07 16:28:24 INFO Serving file. path=/robots.txt
2026/06/07 16:28:24 INFO Serving file. path=/src/lnew.css
2026/06/07 16:28:24 INFO Serving file. path=/src/theme.css
```

**(III) Prevent compromise of the underlying system:** Ajda limits the set of system calls it can make after startup using [seccomp](https://lwn.net/Articles/656307/), which removes the majority of the attack surface. Additionally, Ajda uses [cgroups](https://docs.kernel.org/admin-guide/cgroup-v1/cgroups.html) to limit the amount of CPU and memory resources it can consume, preventing DoS attacks against the server.

Note that it's still a good idea to run Ajda inside an isolated environment, such as a Docker container. Even better, run it on top of [Firecracker](https://firecracker-microvm.github.io/), which provides stronger, hardware-enforced isolation from the rest of the system. Running a web-facing application directly on Linux exposes a large attack surface that can be avoided entirely by using solutions such as Firecracker's microVMs. However, running Ajda on a Raspberry Pi with the default OS is easier. You should perform your own threat modeling to determine whether this simplification is worth it.

**Footnote 1**: With the exception of [libseccomp-golang](https://github.com/seccomp/libseccomp-golang), which is not part of the standard library.

**Footnote 2**: The idea of using file descriptors as a mechanism of controlling access to files comes from the [Capsicum](https://www.usenix.org/legacy/event/sec10/tech/full_papers/Watson.pdf) sandboxing framework available for [FreeBSD](https://man.freebsd.org/cgi/man.cgi?capsicum%284%29). Capsicum uses file descriptors as capabilities to control access to several resources.
