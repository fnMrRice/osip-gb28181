# Building oSIP with CMake

Requires CMake 3.21 or newer and a C11 compiler. The CMake package version is
5.3.2; release provenance and local patches are in `ORIGIN.md` and `PATCHES.md`.

```sh
cmake --preset Debug-native
cmake --build --preset Debug-native
ctest --preset Debug-native
cmake --install build/Debug-native --prefix /path/to/osip-install
```

The presets use Ninja. On Windows, use a Visual Studio developer shell or select
a Visual Studio toolchain in CLion. `Release-native` builds libraries without
enabling test programs. The CMake build has no external package dependencies.

| Option | Default | Behavior |
| --- | --- | --- |
| `BUILD_SHARED_LIBS` | OFF | Build shared instead of static libraries. |
| `OSIP_MONOTHREAD` | OFF | Omit oSIP thread primitives; the application owns scheduling. |
| `OSIP_MINISIZE` | OFF | Omit optional headers and SDP support. |
| `OSIP_ENABLE_TRACE` | ON | Enable oSIP trace messages for the library and consumers. |
| `OSIP_BUILD_TESTS` | OFF | Build and register the upstream parser tools with CTest. |
| `OSIP_INSTALL` | ON | Enable installation and CMake package exports. |

For an installed package, add its prefix to `CMAKE_PREFIX_PATH`:

```cmake
find_package(osip2 5.3.2 CONFIG REQUIRED)
target_link_libraries(my_application PRIVATE osip2::osip2)
```

`osip2::osip2` links the transaction engine and parser; parser-only consumers can
link `osip2::osipparser2`. Both targets are also available with `add_subdirectory`.
Public ABI settings such as monothread and minisize are carried by the targets.
The installed package includes public headers, CMake exports, `libosip2.pc`,
and the LGPL license. Windows shared-library consumers must make the installed
`bin` directory available to the process at runtime.
