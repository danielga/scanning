#pragma once

#include <cstdint>
#include <cstddef>
#include "platform.hpp"

#ifdef SYSTEM_POSIX

#include <vector>
#include <string>
#include <unordered_map>

#endif

class SymbolFinder
{
public:
	SymbolFinder( );

	void *FindPattern( const void *handle, const uint8_t *pattern, size_t len, const void *start = nullptr );
	void *FindPatternFromBinary( const char *name, const uint8_t *pattern, size_t len, const void *start = nullptr );
	void *FindSymbol( const void *handle, const char *symbol );
	void *FindSymbolFromBinary( const char *name, const char *symbol );

	// data can be a symbol name (if appended by @) or a pattern
	void *Resolve( const void *handle, const char *data, size_t len = 0, const void *start = nullptr );
	void *ResolveOnBinary( const char *name, const char *data, size_t len = 0, const void *start = nullptr );

private:
	bool GetLibraryInfo( const void *handle, struct DynLibInfo &info );

#ifdef SYSTEM_POSIX
	typedef std::unordered_map<std::string, void *> SymbolTable;

	struct LibSymbolTable
	{
		LibSymbolTable( uintptr_t base ) :
			table( ), lib_base( base ), last_pos( 0 )
		{ }

		SymbolTable table;
		uintptr_t lib_base;
		uint32_t last_pos;
	};

	std::vector<LibSymbolTable> symbolTables;

#ifdef SYSTEM_MACOSX

	struct dyld_all_image_infos *m_ImageList;

#endif

#endif

};
