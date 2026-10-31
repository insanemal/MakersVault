# BTRFS snapshot sidecar

A small, opt-in helper that lets Curiarium take BTRFS snapshots.

**You probably do not need it.** If your library is on CephFS, ZFS, or anything else, the
API handles snapshots itself — ZFS needs no helper because the `zfs` CLI works with delegated
rights, and CephFS needs none because `.snap` is a kernel view. This container exists for one
case only: `btrfs_subvol`.

The full story — capability states, the compose override to copy, and the invariant that
bites — is in
[CONFIGURATION.md → Snapshots (BTRFS sidecar)](../docs/architecture/CONFIGURATION.md#snapshots-btrfs-sidecar).
Read that before deploying this. What follows is the short version.

## Why a separate container

`btrfs subvolume snapshot` requires `CAP_SYS_ADMIN`, and the API container deliberately runs
without it: the vault holds the household's files, and a web-facing process with the
capability to snapshot — and therefore to destroy — subvolumes is a poor trade. So the
privilege lives here, in a container whose entire job is three narrow operations, and the API
reaches it over the compose network.

## What it does

`server.py` serves three operations on port 8765, each validated by `guard.py`:

- create a snapshot under `<mount>/.snap/<name>`
- list the snapshots this application named
- delete one of them

`guard.py` is the containment layer, and it is the reason this is safe to run privileged: one
bind-mounted subvolume, a name the guard validates and re-contains, argv-only `btrfs` calls
(never a shell), and no published port. Read it before changing anything here.

## Running it

The compose override in CONFIGURATION.md is the supported way. The essentials:

| Setting | Meaning |
|---|---|
| `SNAPSHOT_BTRFS_SIDECAR_TOKEN` | Shared secret; the API sends it, the sidecar rejects everything else. Required. |
| `SNAPSHOT_BTRFS_SIDECAR_URL` | Set **on the API** to `http://snapshot-sidecar:8765`. Empty is the normal, supported state. |
| `SNAPSHOT_BTRFS_SIDECAR_MOUNT` | Where the library subvolume appears inside the sidecar, default `/library`. |

**The invariant:** the sidecar's mount and the API's `FILE_STORAGE` must be the same directory
seen at two paths. The sidecar writes `<mount>/.snap/<name>`; the provider's `list()` reads
`<FILE_STORAGE>/.snap`. Point them at two different directories and nothing fails loudly —
the capability report says usable, every create succeeds, and `list()` stays empty forever.

Build it from this directory (`docker compose` does that for you via
`build: ./snapshot-sidecar`). It is not part of any shipped manifest, and it is not built by
the release workflow.
