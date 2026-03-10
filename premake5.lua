workspace("ProofVote")
startproject("leader_node")
location("build")

configurations({
	"debug_x86",
	"debug_x64",
	"debug_arm64",
	"release_x86",
	"release_x64",
	"release_arm64",
})

-----------------------------------
-- COMMON CONFIG FUNCTION
-----------------------------------

function common_config()
	language("C++")
	cppdialect("C++17")

	targetdir("bin/%{cfg.buildcfg}")
	objdir("build/obj/%{prj.name}/%{cfg.buildcfg}")

	includedirs({ "src" })

	files({
		"src/core/**.h",
		"src/core/**.cpp",
	})

	-- Link dependencies (applies to all projects)
	filter("system:linux")
	links({ "ssl", "crypto", "pthread" })

	filter("system:windows")
	includedirs({ "C:/OpenSSL-Win64/include" })
	libdirs({ "C:/OpenSSL-Win64/lib" })
	links({ "libssl", "libcrypto" })

	filter("system:macosx")
	links({ "ssl", "crypto" })

	filter({})
end

-----------------------------------
-- LEADER NODE
-----------------------------------

project("leader_node")
kind("ConsoleApp")

common_config()

files({
	"src/nodes/leader.cpp",
})

-----------------------------------
-- CLIENT NODE
-----------------------------------

project("client_node")
kind("ConsoleApp")

common_config()

files({
	"src/nodes/client.cpp",
})

-----------------------------------
-- CONFIGURATION FILTERS
-----------------------------------

filter("configurations:debug_x86")
architecture("x86")
defines({ "DEBUG", "LOG_LEVEL_DEBUG" })
symbols("On")

filter("configurations:release_x86")
architecture("x86")
defines({ "NDEBUG", "LOG_LEVEL_INFO" })
optimize("On")

filter("configurations:debug_x64")
architecture("x86_64")
defines({ "DEBUG", "LOG_LEVEL_DEBUG" })
symbols("On")

filter("configurations:release_x64")
architecture("x86_64")
defines({ "NDEBUG", "LOG_LEVEL_INFO" })
optimize("On")

filter("configurations:debug_arm64")
architecture("arm64")
defines({ "DEBUG", "LOG_LEVEL_DEBUG" })
symbols("On")

filter("configurations:release_arm64")
architecture("arm64")
defines({ "NDEBUG", "LOG_LEVEL_INFO" })
optimize("On")

filter({})
