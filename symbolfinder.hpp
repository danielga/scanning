#pragma once

#include <stdint.h>
#include <stddef.h>

#if !defined _WIN32

#include <vector>
#include <map>
#include <string>

#endif

class SymbolFinder
{
public:
	SymbolFinder( );

	void *FindPattern( const void *handle, const uint8_t *pattern, size_t len );
	void *FindPatternFromBinary( const char *name, const uint8_t *pattern, size_t len );
	void *FindSymbol( const void *handle, const char *symbol );
	void *FindSymbolFromBinary( const char *name, const char *symbol );

	// data can be a symbol name (if appended by @) or a pattern
	void *Resolve( const void *handle, const char *data, size_t len = 0 );
	void *ResolveOnBinary( const char *name, const char *data, size_t len = 0 );

private:
	bool GetLibraryInfo( const void *handle, struct DynLibInfo &info );

#if defined __linux || defined __APPLE__

	struct LibSymbolTable
	{
		LibSymbolTable( uintptr_t base ) :
			table( ), lib_base( base ), last_pos( 0 )
		{ }

		std::map<std::string, void *> table;
		uintptr_t lib_base;
		uint32_t last_pos;
	};

	std::vector<LibSymbolTable> symbolTables;

#endif

#if defined __APPLE__

	struct dyld_all_image_infos *m_ImageList;
	int m_OSXMajor;
	int m_OSXMinor;

#endif

};