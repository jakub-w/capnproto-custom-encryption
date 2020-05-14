project('capnproto-custom-encryption', 'cpp',
	default_options: 'cpp_std=c++17')


# Build types
if get_option('buildtype').startswith('debug')
  add_project_arguments('-Wall', '-Wextra', '-DFORTIFY_SOURCE=1',
                        '-ggdb3',
                        '-fsanitize=address',
                        # '-fsanitize=leak',
                        # '-fsanitize=undefined',
                        language : 'cpp')
  add_project_link_arguments(
    '-lasan',
    # '-ltsan',
    # '-lubsan',
    language : 'cpp')
elif get_option('buildtype') == 'release'
  add_project_arguments('-DNDEBUG', '-O3', '-s',
                        language : 'cpp')
endif


# Dependencies
capnp_dep = dependency('capnp')
capnp_rpc_dep = dependency('capnp-rpc')
libsodium_dep = dependency('libsodium')

# Cap'n'proto
capnp = find_program('capnp')
gen_capnp = generator(capnp,
		      arguments: ['compile',
				  '--output=c++:@BUILD_DIR@',
				  '--src-prefix=@CURRENT_SOURCE_DIR@',
				  '@INPUT@'],
		      output: ['@PLAINNAME@.c++', '@PLAINNAME@.h'])
capnp_files = gen_capnp.process('messages.capnp')

# This will create a static library that will be put inside of all resulting
# executables. It could be better to make a shared library if we have more
# execs.
# Making capnp_files a library is good because we don't generate the same
# capnp files every time we put them as sources in an build target object.
capnp_generated = static_library('capnp_generated',
				 capnp_files)


expected_dir = include_directories('expected/include')

# executable('custom-rpc',
# 	   sources: ['custom-rpc.cpp'],
# 	   link_with: capnp_generated,
# 	   include_directories: [capnp_generated.private_dir_include(),
# 				 expected_dir],
# 	   dependencies: [capnp_dep, capnp_rpc_dep, libsodium_dep])

subdir('test')
