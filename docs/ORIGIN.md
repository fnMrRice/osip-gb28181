# GNU oSIP source provenance

The upstream baseline is the official GNU oSIP **5.3.2** release (2026-07-23):

- Release archive: https://ftp.gnu.org/gnu/osip/libosip2-5.3.2.tar.gz
- SHA256: `16186f6f5540936b62c3aaca6e8409e1af25cd22abc3882b393be215f49d3b00`
- Upstream Git: https://git.savannah.gnu.org/git/osip.git
- Git ancestor: `e2cd483bb668f47e089ee3be9df035ff3281b4af` (2026-07-20)
- Release archive verified on: 2026-11-16
- Fork branch: `main`
- License: LGPL-2.1-or-later; see `COPYING` and source notices.

All 104 production C/header files in the Git ancestor are byte-for-byte identical
with the 5.3.2 release. The release version metadata, ChangeLog, enabled SDP
regression, and additional test fixtures have been imported from the verified
archive. Autotools-generated files and editor backup files are not vendored.
The upstream Git repository has no 5.3.2 tag; no synthetic upstream tag is created.

Local generic authentication, length handling, platform headers, and CMake
changes are described in `PATCHES.md`. Applications that own scheduling can enable OSIP_MONOTHREAD.
