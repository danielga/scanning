local current_dir = _SCRIPT_DIR

function IncludeScanning()
	local refcount = IncludePackage("scanning")

	local _project = project()

	sysincludedirs(current_dir .. "/include")
	links("scanning")

	filter("system:macosx")
		links("CoreServices.framework")

	if refcount == 1 then
		dofile(current_dir .. "/premake5_create_project.lua")
	end

	project(_project.name)
end
