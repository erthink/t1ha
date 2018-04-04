## meson.build for t1ha v2.0.1

project('t1ha', 'c')

cc = meson.get_compiler('c')
t1ha_sources = files(
  'src/t1ha0.c',
  'src/t1ha1.c',
  'src/t1ha2.c')

t1ha_objects = []
t1ha_c_args = []
t1ha_link_with = []

foreach a : ['-Wall', '-ffunction-sections', '-std=c99']
  if cc.has_argument(a)
    t1ha_c_args += a
  endif
endforeach

if true
  t1ha_c_args = ['-Dt1ha_EXPORTS']
  if cc.has_argument('-fvisibility=hidden')
    t1ha_c_args += '-fvisibility=hidden'
  endif
endif

if target_machine.cpu_family().startswith('x86')
  t1ha_ia32aes_noavx_c_args = t1ha_c_args
  t1ha_ia32aes_avx_c_args = t1ha_c_args
  t1ha_ia32aes_avx2_c_args = t1ha_c_args

  if cc.get_id() == 'msvc'
    t1ha_ia32aes_avx_c_args += '/arch:AVX'
    t1ha_ia32aes_avx2_c_args += '/arch:AVX2'
  else
    t1ha_ia32aes_noavx_c_args += ['-mno-avx2', '-mno-avx', '-maes', '-mtune=native']
    t1ha_ia32aes_avx_c_args += ['-mno-avx2', '-mavx', '-maes', '-mtune=native']
    t1ha_ia32aes_avx2_c_args += ['-mavx2', '-mavx', '-maes', '-mtune=native']
  endif

  # Need a staging lib since meson cannot set c_args per object.
  # Need all versions since th1a0 hash checks processor and chooses
  # the appropriate version at runtime.
  lib = static_library('t1ha_ia32aes_noavx_stage',
        'src/t1ha0_ia32aes_noavx.c', c_args: t1ha_ia32aes_noavx_c_args)
  t1ha_objects += lib.extract_objects('src/t1ha0_ia32aes_noavx.c')

  lib = static_library('t1ha_ia32aes_avx_stage',
        'src/t1ha0_ia32aes_avx.c', c_args: t1ha_ia32aes_avx_c_args)
  t1ha_objects += lib.extract_objects('src/t1ha0_ia32aes_avx.c')

  lib = static_library('t1ha_ia32aes_avx2_stage',
        'src/t1ha0_ia32aes_avx2.c', c_args: t1ha_ia32aes_avx2_c_args)
  t1ha_objects += lib.extract_objects('src/t1ha0_ia32aes_avx2.c')
endif

libt1ha = static_library('t1ha', t1ha_sources, c_args: t1ha_c_args, objects: t1ha_objects)

## this makes it possible to use the source and objects in parent project without using libt1ha directly.
#lib_objects += t1ha_objects
#lib_sources += t1ha_sources
