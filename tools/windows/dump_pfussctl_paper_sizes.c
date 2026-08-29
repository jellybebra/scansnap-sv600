#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void
dump_double(const unsigned char *base, uintptr_t virtual_address)
{
  double value;

  memcpy(&value, base + virtual_address - 0x10000000u, sizeof(value));
  printf("%08lx %.17g\n", (unsigned long)virtual_address, value);
}

int
main(int argc, char **argv)
{
  static const uintptr_t pfussctl_addresses[] = {
    /* ScanSnap Home 4.0 PfuSsCtl.dll constants. */
    0x1025d548, 0x1025d558, 0x1025d580, 0x1025d598,
    0x1025d5a0, 0x1025d628, 0x1025d630, 0x1025d638,
    0x1025d5a8, 0x1025d5b0, 0x1025d5b8, 0x1025d5c0,
    0x1025d5c8, 0x1025d5d0, 0x1025d5d8, 0x1025d5e0,
    0x1025d5e8, 0x1025d5f0, 0x1025d5f8, 0x1025d600,
    0x1025d608,
    0x1025d640, 0x1025d648, 0x1025d650, 0x1025d658,
    0x1025d660, 0x1025d668, 0x1025d670, 0x1025d678,
    0x1025d680, 0x1025d688, 0x1025d690, 0x1025d698,
    0x1025d6a0, 0x1025d6a8, 0x1025d6c0, 0x1025d6c8,
    0x1025d6d0, 0x1025d6d8, 0x1025d6e0, 0x1025d6e8,
    0x1025d6f0, 0x1025d6f8, 0x1025d700, 0x1025d708,
    0x1025d710, 0x1025d718, 0x1025d720, 0x1025d728,
    0x1025d740, 0x1025d748
  };
  static const uintptr_t sshctl_addresses[] = {
    /* ScanSnap Home 3.7 SshCtl.dll constants used by SetPreReadMode. */
    0x102ca060, 0x102ca068, 0x102ca088, 0x102ca0b0,
    0x102ca0d8, 0x102ca0f0, 0x102ca100, 0x102ca110,
    0x102ca120, 0x102ca138, 0x102ca190, 0x102ca1d8,
    0x102ca1e8, 0x102ca1f0,
  };
  const uintptr_t *addresses;
  size_t count;
  int module_index;
  size_t index;

  if (argc != 3) {
    fprintf(stderr, "usage: %s PfuSsCtl.dll SshCtl.dll\n", argv[0]);
    return 2;
  }
  for (module_index = 1; module_index < argc; module_index++) {
    HMODULE module = LoadLibraryA(argv[module_index]);

    if (!module) {
      fprintf(stderr, "LoadLibrary(%s) failed: %lu\n",
              argv[module_index], GetLastError());
      return 1;
    }
    if (module_index == 1) {
      addresses = pfussctl_addresses;
      count = sizeof(pfussctl_addresses) / sizeof(pfussctl_addresses[0]);
    }
    else {
      addresses = sshctl_addresses;
      count = sizeof(sshctl_addresses) / sizeof(sshctl_addresses[0]);
    }
    printf("[%s]\n", argv[module_index]);
    for (index = 0; index < count; index++)
      dump_double((const unsigned char *)module, addresses[index]);
    FreeLibrary(module);
  }
  return 0;
}
