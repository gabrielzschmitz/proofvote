workspace("ProofVote")
startproject("proofvote")

configurations({
	"debug_x86",
	"debug_x64",
	"debug_arm64",
	"release_x86",
	"release_x64",
	"release_arm64",
})

project("proofvote")
kind("ConsoleApp")
language("C++")
cppdialect("C++17")
location("build")

targetdir("bin/%{cfg.buildcfg}")
objdir("build/obj/%{cfg.buildcfg}")

files({ "src/**.h", "src/**.cpp" })
includedirs({ "src" })

--------------------
-- CONFIGURATION FILTERS
--------------------
-- x86
filter("configurations:debug_x86")
architecture("x86")
defines({ "DEBUG", "LOG_LEVEL_DEBUG" })
symbols("On")

filter("configurations:release_x86")
architecture("x86")
defines({ "NDEBUG", "LOG_LEVEL_INFO" })
optimize("On")

-- x64
filter("configurations:debug_x64")
architecture("x86_64")
defines({ "DEBUG", "LOG_LEVEL_DEBUG" })
symbols("On")

filter("configurations:release_x64")
architecture("x86_64")
defines({ "NDEBUG", "LOG_LEVEL_INFO" })
optimize("On")

-- ARM64
filter("configurations:debug_arm64")
architecture("arm64")
defines({ "DEBUG", "LOG_LEVEL_DEBUG" })
symbols("On")

filter("configurations:release_arm64")
architecture("arm64")
defines({ "NDEBUG", "LOG_LEVEL_INFO" })
optimize("On")

--------------------
-- PLATFORM SPECIFIC
--------------------
-- Linux
filter("system:linux")
links({ "ssl", "crypto", "pthread" })
buildoptions({
	"-pthread",
	"`pkg-config --cflags openssl`",
})
linkoptions({
	"-pthread",
	"`pkg-config --libs openssl`",
})

-- Windows
filter("system:windows")
includedirs({ "C:/OpenSSL-Win64/include" })
libdirs({ "C:/OpenSSL-Win64/lib" })
links({ "libssl", "libcrypto" })

-- macOS
filter("system:macosx")
buildoptions({
	"-pthread",
	"-Wno-deprecated-declarations",
	"`pkg-config --cflags openssl`",
})
linkoptions({
	"-pthread",
	"`pkg-config --libs openssl`",
})
