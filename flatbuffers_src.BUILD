genrule(
    name = "flatc",
    srcs = glob(["**"]),
    outs = ["flatc_bin"],
    cmd = """
        CMAKEFILE=$(location CMakeLists.txt)
        SRCDIR=$$(realpath $$(dirname $$CMAKEFILE))
        BUILDDIR=$$(mktemp -d)
        cmake -B $$BUILDDIR -S $$SRCDIR -DCMAKE_BUILD_TYPE=Release -DFLATBUFFERS_BUILD_TESTS=OFF 2>&1
        cmake --build $$BUILDDIR --target flatc -j$$(nproc) 2>&1
        cp $$BUILDDIR/flatc $@
    """,
    visibility = ["//visibility:public"],
)
