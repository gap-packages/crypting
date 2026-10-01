This file describes changes in the crypting package.

## 0.10.7 (2026-08-18)

- Rename `IsSHA256State` to `IsCryptingSHA256State`, freeing the name for the
  GAP library (#27)
- Drop the dependency on GAPDoc (#26)

## 0.10.6 (2025-06-20)

- Fix the return value of the availability test when the kernel module is
  missing

## 0.10.5 (2024-09-03)

- Require GAP >= 4.12
- Use `IsKernelExtensionAvailable` in the availability test and warn when the
  kernel module is not compiled (gap-system/gap#5761)

## 0.10.4 (2022-11-02)

- Detect endianness at compile time
- Simplify the build system

## 0.10.3 (2022-10-06)

- Include `compiled.h` instead of `src/compiled.h`, for compatibility with
  future GAP versions

## 0.10.2 (2022-09-09)

- Janitorial changes

## 0.10.1 (2021-02-24)

- Janitorial changes

## 0.10 (2019-10-28)

## 0.9 (2018-09-22)

## 0.8 (2018-05-25)

## 0.7 (2017-10-17)

## 0.6 (2017-08-20)

## 0.5 (2017-08-20)

## 0.4 (2017-03-04)

## 0.3 (2017-03-04)

## 0.2 (2017-03-02)

## 0.1 (2017-03-02)
