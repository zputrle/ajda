---
title: Ajda
author: zputrle
---

**Ajda** is a reasonably secure minimal HTTPS server that:

- is as **simple** as possible,
- written in **Go**,
- **easily understood and reviewed**.
- contained in a **single file**,
- is **secure by default**,
- **serves only a fixed set of files**, and
- runs on Linux (e.g. Debian).

Perfect for self-hosting a blog.

See the [code](https://github.com/zputrle/ajda/blob/main/src/ajda.go).


[Home](https://ajda.fly.dev/ajda.html) / [GitHub](https://github.com/zputrle/ajda/)

## How to run

Run
```bash
go run src/ajda.go --rootDirPath ./pages/ --address :8080 --home ajda.html \
  --server_cert cert/server.crt --server_key cert/server.key 
```

Expected output:
```
2026/06/07 16:28:24 INFO Starting ...
2026/06/07 16:28:24 INFO Serving file. path=/ajda.html
2026/06/07 16:28:24 INFO Serving file. path=/robots.txt
2026/06/07 16:28:24 INFO Serving file. path=/src/lnew.css
2026/06/07 16:28:24 INFO Serving file. path=/src/theme.css
2026/06/07 16:28:24 INFO Limiting the number of cores and memory. #cores=1 memory(MB)=512
2026/06/07 16:28:24 INFO Restricting file access. to_path=<path_to_root_dir>
2026/06/07 16:28:24 INFO Whitelisting system calls. system_calls="write, epoll_ctl, close, exit_group, accept4, nanosleep, epoll_pwait, futex, sched_yield, read, mmap, getsockname, setsockopt, prctl, getrandom, lseek, openat, rt_sigprocmask, getpid, tgkill, gettid, fsync, rt_sigreturn, rt_sigaction"
2026/06/07 16:28:24 INFO Listening ... on_address=:8080
```

Get additional information about the flags:
```bash
go run src/ajda.go --help
```

## Security

The idea behind Ajda is simple: we want to self-host a blog on a Raspberry Pi while being reasonably sure that Ajda **(I)** serves only a predefined set of files selected at startup, and **(II)** does not represent a convenient entry point for an attacker. We assume that the attacker is attempting to compromise Ajda through the exposed HTTPS port where Ajda is listening.

Ajda follows a simple idea: **programs should permanently restrict what they can do at startup**. For example, programs should always limit which system calls they can make and which files they can access. As a result, even if a program is compromised, an attacker cannot make arbitrary system calls or interact with arbitrary files. The goal is to reduce the attack surface as much as possible when the program is compromised.

**(I) Serve only selected files**: Ajda serves only files that are present in the _root directory_ at startup. When Ajda starts, it creates an allowlist of all files in the root directory. If the file is on the list, it can be served; otherwise the request is rejected. Ajda displays the allowlist at startup.

Furthermore, Ajda uses [Landlock](https://landlock.io/) to restrict itself so that it can only read files from the root directory. Therefore, even if Ajda were compromised and coerced into bypassing the allowlist check, it would still only be able to read files from the root directory. This prevents Ajda from interacting with arbitrary files elsewhere on the system, significantly reducing the attack surface.

In addition, Ajda also uses Go's [os.Root](https://go.dev/blog/osroot) to avoid path traversal, as paths are controlled by the clients. This is partially redundant because Ajda is already restricted to the root directory by Landlock and the allowlist check, but os.Root is easy to add.

**(II) Prevent underlying system from being compromised:**  
Alongside using Landlock, Ajda restricts the set of system calls it can make using [seccomp](https://lwn.net/Articles/656307/), effectively blocking the majority of system calls. Additionally, Ajda uses [cgroups](https://docs.kernel.org/admin-guide/cgroup-v1/cgroups.html) to limit the amount of CPU and memory resources it can consume. So even if an attacker performs a DoS attack, it will only impact Ajda and not the rest of the system.

**Note**: A preferred way to run Ajda is still inside a container, or even better, on top of [Firecracker](https://firecracker-microvm.github.io/), which provides stronger, hardware-enforced isolation from the rest of the system. Running a web-facing application directly on Linux exposes a large attack surface that can be avoided entirely by using solutions such as Firecracker's microVMs. However, running Ajda on a Raspberry Pi with the default OS is easier. Note that, you should perform your own threat modeling to determine whether this simplification is worth it.
