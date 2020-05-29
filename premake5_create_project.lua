group("garrysmod_common")
	project("scanning")
		kind("StaticLib")
		location("projects/" .. os.target() .. "/" .. _ACTION)
		targetdir("%{prj.location}/%{cfg.architecture}/%{cfg.buildcfg}")
		debugdir("%{prj.location}/%{cfg.architecture}/%{cfg.buildcfg}")
		objdir("!%{prj.location}/%{cfg.architecture}/%{cfg.buildcfg}/intermediate/%{prj.name}")
		includedirs("include/scanning")
		files({
			"include/*.hpp",
			"source/*.cpp"
		})
		vpaths({
			["Header files/*"] = "include/*.hpp",
			["Source files/*"] = "source/*.cpp"
		})

		filter("system:linux or macosx")
			links("dl")
