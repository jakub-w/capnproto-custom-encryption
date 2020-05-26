gtest_dep = dependency('gtest')
gmock_dep = [dependency('gmock')]

test_capnp = gen_capnp.process('test.capnp')

test_all = executable('test_all',
		      sources: ['test.cpp',
				'InsecureChannel-test.cpp',
				'EncryptedConnection-test.cpp',
				'Channel-test.cpp',
				'EncryptionCommon-test.cpp',
				test_capnp],
		      include_directories: expected_dir,
		      dependencies: [gtest_dep,
				     gmock_dep,
				     capnp_dep, capnp_rpc_dep,
				     libsodium_dep],
		      cpp_args: '-Wno-unused-result')

test('zkp', test_all,
     args: ['--gtest_repeat=1000',
	    '--gtest_filter=EncryptionCommon.ZKP'],
     # protocol: 'gtest'
    )

test('all', test_all)
