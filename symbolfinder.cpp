#include "symbolfinder.hpp"
#include "platform.hpp"

#if defined SYSTEM_WINDOWS

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

#elif defined SYSTEM_LINUX

#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define PAGE_ALIGN_UP( x ) ( ( x + PAGE_SIZE - 1 ) & ~( PAGE_SIZE - 1 ) )

#elif defined SYSTEM_MACOSX

#import <CoreServices/CoreServices.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <sys/mman.h>
#include <dlfcn.h>

#endif

struct DynLibInfo
{
	void *baseAddress;
	size_t memorySize;
};

SymbolFinder::SymbolFinder( )
{

#if defined SYSTEM_MACOSX

	task_dyld_info_data_t dyld_info;
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	task_info( mach_task_self( ), TASK_DYLD_INFO, reinterpret_cast<task_info_t>( &dyld_info ), &count );
	m_ImageList = reinterpret_cast<struct dyld_all_image_infos *>( dyld_info.all_image_info_addr );

#endif

}

void *SymbolFinder::FindPattern( const void *handle, const uint8_t *pattern, size_t len, const void *start )
{
	DynLibInfo lib;
	memset( &lib, 0, sizeof( DynLibInfo ) );
	if( !GetLibraryInfo( handle, lib ) )
		return nullptr;

	uint8_t *ptr = reinterpret_cast<uint8_t *>( start > lib.baseAddress ? const_cast<void *>( start ) : lib.baseAddress );
	uint8_t *end = reinterpret_cast<uint8_t *>( lib.baseAddress ) + lib.memorySize - len;
	bool found = true;
	while( ptr < end )
	{
		for( size_t i = 0; i < len; ++i )
			if( pattern[i] != '\x2A' && pattern[i] != ptr[i] )
			{
				found = false;
				break;
			}

		if( found )
			return ptr;

		++ptr;
		found = true;
	}

	return nullptr;
}

void *SymbolFinder::FindPatternFromBinary( const char *name, const uint8_t *pattern, size_t len, const void *start )
{

#if defined SYSTEM_WINDOWS

	HMODULE binary = nullptr;
	if( GetModuleHandleEx( 0, name, &binary ) == TRUE && binary != nullptr )
	{
		void *symbol_pointer = FindPattern( binary, pattern, len, start );
		FreeModule( binary );
		return symbol_pointer;
	}

#elif defined SYSTEM_POSIX

	void *binary = dlopen( name, RTLD_LAZY | RTLD_NOLOAD );
	if( binary != nullptr)
	{
		void *symbol_pointer = FindPattern( binary, pattern, len, start );
		dlclose( binary );
		return symbol_pointer;
	}

#endif

	return nullptr;
}

void *SymbolFinder::FindSymbol( const void *handle, const char *symbol )
{

#if defined SYSTEM_WINDOWS

	return GetProcAddress( reinterpret_cast<HMODULE>( const_cast<void *>( handle ) ), symbol );

#elif defined SYSTEM_LINUX

#if defined ARCHITECTURE_X86
	
	typedef Elf32_Ehdr Elf_Ehdr;
	typedef Elf32_Shdr Elf_Shdr;
	typedef Elf32_Sym Elf_Sym;
#define ELF_ST_TYPE ELF32_ST_TYPE
	
#elif defined ARCHITECTURE_X86_64
	
	typedef Elf64_Ehdr Elf_Ehdr;
	typedef Elf64_Shdr Elf_Shdr;
	typedef Elf64_Sym Elf_Sym;
#define ELF_ST_TYPE ELF64_ST_TYPE
	
#endif
	
	const struct link_map *dlmap = reinterpret_cast<const struct link_map *>( handle );
	LibSymbolTable *libtable = nullptr;
	for( size_t i = 0; i < symbolTables.size( ); ++i )
		if( symbolTables[i].lib_base == dlmap->l_addr )
		{
			libtable = &symbolTables[i];
			break;
		}

	if( libtable == nullptr )
	{
		symbolTables.push_back( LibSymbolTable( dlmap->l_addr ) );
		libtable = &symbolTables.back( );
	}

	SymbolTable &table = libtable->table;
	void *symbol_ptr = table[symbol];
	if( symbol_ptr != nullptr )
		return symbol_ptr;

	struct stat64 dlstat;
	int dlfile = open( dlmap->l_name, O_RDONLY );
	if( dlfile == -1 || fstat64( dlfile, &dlstat ) == -1 )
	{
		close( dlfile );
		return nullptr;
	}

	Elf_Ehdr *file_hdr = reinterpret_cast<Elf_Ehdr *>( mmap( 0, dlstat.st_size, PROT_READ, MAP_PRIVATE, dlfile, 0 ) );
	uintptr_t map_base = reinterpret_cast<uintptr_t>( file_hdr );
	close( dlfile );
	if( file_hdr == MAP_FAILED )
		return nullptr;

	if( file_hdr->e_shoff == 0 || file_hdr->e_shstrndx == SHN_UNDEF )
	{
		munmap( file_hdr, dlstat.st_size );
		return nullptr;
	}

	Elf_Shdr *symtab_hdr = nullptr, *strtab_hdr = nullptr;
	Elf_Shdr *sections = reinterpret_cast<Elf_Shdr *>( map_base + file_hdr->e_shoff );
	uint16_t section_count = file_hdr->e_shnum;
	Elf_Shdr *shstrtab_hdr = &sections[file_hdr->e_shstrndx];
	const char *shstrtab = reinterpret_cast<const char *>( map_base + shstrtab_hdr->sh_offset );
	for( uint16_t i = 0; i < section_count; i++ )
	{
		Elf_Shdr &hdr = sections[i];
		const char *section_name = shstrtab + hdr.sh_name;
		if( strcmp( section_name, ".symtab" ) == 0 )
			symtab_hdr = &hdr;
		else if( strcmp( section_name, ".strtab" ) == 0 )
			strtab_hdr = &hdr;
	}

	if( symtab_hdr == nullptr || strtab_hdr == nullptr )
	{
		munmap( file_hdr, dlstat.st_size );
		return nullptr;
	}

	Elf_Sym *symtab = reinterpret_cast<Elf_Sym *>( map_base + symtab_hdr->sh_offset );
	const char *strtab = reinterpret_cast<const char *>( map_base + strtab_hdr->sh_offset );
	uint32_t symbol_count = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
	void *symbol_pointer = nullptr;
	for( uint32_t i = libtable->last_pos; i < symbol_count; i++ )
	{
		Elf_Sym &sym = symtab[i];
		uint8_t sym_type = ELF_ST_TYPE( sym.st_info );
		const char *sym_name = strtab + sym.st_name;

		if( sym.st_shndx == SHN_UNDEF || ( sym_type != STT_FUNC && sym_type != STT_OBJECT ) )
			continue;

		void *symptr = reinterpret_cast<void *>( dlmap->l_addr + sym.st_value );
		table[sym_name] = symptr;
		if( strcmp( sym_name, symbol ) == 0 )
		{
			libtable->last_pos = ++i;
			symbol_pointer = symptr;
			break;
		}
	}

	munmap( file_hdr, dlstat.st_size );
	return symbol_pointer;

#elif defined SYSTEM_MACOSX

#if defined ARCHITECTURE_X86
	
	typedef struct mach_header mach_header_t;
	typedef struct segment_command segment_command_t;
	typedef struct nlist nlist_t;
	const uint32_t LC_SEGMENT_VALUE = LC_SEGMENT;
	
#elif defined ARCHITECTURE_X86_64
	
	typedef struct mach_header_64 mach_header_t;
	typedef struct segment_command_64 segment_command_t;
	typedef struct nlist_64 nlist_t;
	const uint32_t LC_SEGMENT_VALUE = LC_SEGMENT_64;
	
#endif

	typedef struct load_command load_command_t;
	typedef struct symtab_command symtab_command_t;

	DynLibInfo lib;
	if( !GetLibraryInfo( handle, lib ) )
		return nullptr;

	uintptr_t dlbase = reinterpret_cast<uintptr_t>( lib.baseAddress );
	LibSymbolTable *libtable = nullptr;
	for( size_t i = 0; i < symbolTables.size( ); ++i )
		if( symbolTables[i].lib_base == dlbase )
		{
			libtable = &symbolTables[i];
			break;
		}

	if( libtable == nullptr )
	{
		symbolTables.push_back( LibSymbolTable( dlbase ) );
		libtable = &symbolTables.back( );
	}

	SymbolTable &table = libtable->table;
	void *symbol_ptr = table[symbol];
	if( symbol_ptr != nullptr )
		return symbol_ptr;

	segment_command_t *linkedit_hdr = nullptr;
	symtab_command_t *symtab_hdr = nullptr;
	mach_header_t *file_hdr = reinterpret_cast<mach_header_t *>( dlbase );
	load_command_t *loadcmds = reinterpret_cast<load_command_t *>( dlbase + sizeof( mach_header_t ) );
	uint32_t loadcmd_count = file_hdr->ncmds;
	for( uint32_t i = 0; i < loadcmd_count; i++ )
	{
		if( loadcmds->cmd == LC_SEGMENT_VALUE && linkedit_hdr == nullptr )
		{
			segment_command_t *seg = reinterpret_cast<segment_command_t *>( loadcmds );
			if( strcmp( seg->segname, "__LINKEDIT" ) == 0 )
			{
				linkedit_hdr = seg;
				if( symtab_hdr != nullptr)
					break;
			}
		}
		else if( loadcmds->cmd == LC_SYMTAB )
		{
			symtab_hdr = reinterpret_cast<symtab_command_t *>( loadcmds );
			if( linkedit_hdr != nullptr )
				break;
		}

		loadcmds = reinterpret_cast<load_command_t *>( reinterpret_cast<uintptr_t>( loadcmds ) + loadcmds->cmdsize );
	}

	if( linkedit_hdr == nullptr || symtab_hdr == nullptr || symtab_hdr->symoff == 0 || symtab_hdr->stroff == 0 )
		return nullptr;

	uintptr_t linkedit_addr = dlbase + linkedit_hdr->vmaddr;
	nlist_t *symtab = reinterpret_cast<nlist_t *>( linkedit_addr + symtab_hdr->symoff - linkedit_hdr->fileoff );
	const char *strtab = reinterpret_cast<const char *>( linkedit_addr + symtab_hdr->stroff - linkedit_hdr->fileoff );
	uint32_t symbol_count = symtab_hdr->nsyms;
	void *symbol_pointer = nullptr;
	for( uint32_t i = libtable->last_pos; i < symbol_count; i++ )
	{
		nlist_t &sym = symtab[i];
		const char *sym_name = strtab + sym.n_un.n_strx + 1;
		if( sym.n_sect == NO_SECT )
			continue;

		void *symptr = reinterpret_cast<void *>( dlbase + sym.n_value );
		table[sym_name] = symptr;
		if( strcmp( sym_name, symbol ) == 0 )
		{
			libtable->last_pos = ++i;
			symbol_pointer = symptr;
			break;
		}
	}

	return symbol_pointer;

#endif

}

void *SymbolFinder::FindSymbolFromBinary( const char *name, const char *symbol )
{

#if defined SYSTEM_WINDOWS

	HMODULE binary = nullptr;
	if( GetModuleHandleEx( 0, name, &binary ) == TRUE && binary != nullptr )
	{
		void *symbol_pointer = FindSymbol( binary, symbol );
		FreeModule( binary );
		return symbol_pointer;
	}

#elif defined SYSTEM_POSIX

	void *binary = dlopen( name, RTLD_LAZY | RTLD_NOLOAD );
	if( binary != nullptr )
	{
		void *symbol_pointer = FindSymbol( binary, symbol );
		dlclose( binary );
		return symbol_pointer;
	}

#endif

	return nullptr;
}

void *SymbolFinder::Resolve( const void *handle, const char *data, size_t len, const void *start )
{
	if( len == 0 && data[0] == '@' )
		return FindSymbol( handle, ++data );

	if( len != 0 )
		return FindPattern( handle, reinterpret_cast<const uint8_t *>( data ), len, start );

	return nullptr;
}

void *SymbolFinder::ResolveOnBinary( const char *name, const char *data, size_t len, const void *start )
{
	if( len == 0 && data[0] == '@' )
		return FindSymbolFromBinary( name, ++data );

	if( len != 0 )
		return FindPatternFromBinary( name, reinterpret_cast<const uint8_t *>( data ), len, start );

	return nullptr;
}

bool SymbolFinder::GetLibraryInfo( const void *handle, DynLibInfo &lib )
{
	if( handle == nullptr )
		return false;

#if defined SYSTEM_WINDOWS

#if defined ARCHITECTURE_X86
	
	const WORD IMAGE_FILE_MACHINE = IMAGE_FILE_MACHINE_I386;
	
#elif defined ARCHITECTURE_X86_64
	
	const WORD IMAGE_FILE_MACHINE = IMAGE_FILE_MACHINE_AMD64;
	
#endif

	MEMORY_BASIC_INFORMATION info;
	if( VirtualQuery( handle, &info, sizeof( info ) ) == FALSE )
		return false;

	uintptr_t baseAddr = reinterpret_cast<uintptr_t>( info.AllocationBase );

	IMAGE_DOS_HEADER *dos = reinterpret_cast<IMAGE_DOS_HEADER *>( baseAddr );
	IMAGE_NT_HEADERS *pe = reinterpret_cast<IMAGE_NT_HEADERS *>( baseAddr + dos->e_lfanew );
	IMAGE_FILE_HEADER *file = &pe->FileHeader;
	IMAGE_OPTIONAL_HEADER *opt = &pe->OptionalHeader;

	if( dos->e_magic != IMAGE_DOS_SIGNATURE || pe->Signature != IMAGE_NT_SIGNATURE || opt->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC )
		return false;

	if( file->Machine != IMAGE_FILE_MACHINE )
		return false;

	if( ( file->Characteristics & IMAGE_FILE_DLL ) == 0 )
		return false;

	lib.memorySize = opt->SizeOfImage;

#elif defined SYSTEM_LINUX

#if defined ARCHITECTURE_X86
	
	typedef Elf32_Ehdr Elf_Ehdr;
	typedef Elf32_Phdr Elf_Phdr;
	const unsigned char ELFCLASS = ELFCLASS32;
	const uint16_t EM = EM_386;
	
#elif defined ARCHITECTURE_X86_64
	
	typedef Elf64_Ehdr Elf_Ehdr;
	typedef Elf64_Phdr Elf_Phdr;
	const unsigned char ELFCLASS = ELFCLASS64;
	const uint16_t EM = EM_X86_64;
	
#endif
	
	const struct link_map *map = static_cast<const struct link_map *>( handle );
	uintptr_t baseAddr = reinterpret_cast<uintptr_t>( map->l_addr );
	Elf_Ehdr *file = reinterpret_cast<Elf_Ehdr *>( baseAddr );
	if( memcmp( ELFMAG, file->e_ident, SELFMAG ) != 0 )
		return false;

	if( file->e_ident[EI_VERSION] != EV_CURRENT )
		return false;

	if( file->e_ident[EI_CLASS] != ELFCLASS || file->e_machine != EM || file->e_ident[EI_DATA] != ELFDATA2LSB )
		return false;

	if( file->e_type != ET_DYN )
		return false;

	uint16_t phdrCount = file->e_phnum;
	Elf_Phdr *phdr = reinterpret_cast<Elf_Phdr *>( baseAddr + file->e_phoff );
	for( uint16_t i = 0; i < phdrCount; ++i )
	{
		Elf_Phdr &hdr = phdr[i];
		if( hdr.p_type == PT_LOAD && hdr.p_flags == ( PF_X | PF_R ) )
		{
			lib.memorySize = PAGE_ALIGN_UP( hdr.p_filesz );
			break;
		}
	}

#elif defined SYSTEM_MACOSX

#if defined ARCHITECTURE_X86
	
	typedef struct mach_header mach_header_t;
	typedef struct segment_command segment_command_t;
	const uint32_t MH_MAGIC_VALUE = MH_MAGIC;
	const uint32_t LC_SEGMENT_VALUE = LC_SEGMENT;
	const cpu_type_t CPU_TYPE = CPU_TYPE_I386;
	const cpu_subtype_t CPU_SUBTYPE = CPU_SUBTYPE_I386_ALL;
	
#elif defined ARCHITECTURE_X86_64
	
	typedef struct mach_header_64 MachHeader;
	typedef struct segment_command_64 MachSegment;
	const uint32_t MH_MAGIC_VALUE = MH_MAGIC_64;
	const uint32_t LC_SEGMENT_VALUE = LC_SEGMENT_64;
	const cpu_type_t CPU_TYPE = CPU_TYPE_X86_64;
	const cpu_subtype_t CPU_SUBTYPE = CPU_SUBTYPE_X86_64_ALL;
	
#endif
	
	uintptr_t baseAddr = 0;
	for( uint32_t i = 1; i < m_ImageList->infoArrayCount; ++i )
	{
		const struct dyld_image_info &info = m_ImageList->infoArray[i];
		void *h = dlopen( info.imageFilePath, RTLD_LAZY | RTLD_NOLOAD );
		if( h == handle )
		{
			baseAddr = reinterpret_cast<uintptr_t>( info.imageLoadAddress );
			dlclose( h );
			break;
		}

		dlclose( h );
	}

	if( baseAddr == 0 )
		return false;

	mach_header_t *file = reinterpret_cast<mach_header_t *>( baseAddr );
	if( file->magic != MH_MAGIC_VALUE )
		return false;

	if( file->cputype != CPU_TYPE || file->cpusubtype != CPU_SUBTYPE )
		return false;

	if( file->filetype != MH_DYLIB )
		return false;

	uint32_t cmd_count = file->ncmds;
	segment_command_t *seg = reinterpret_cast<segment_command_t *>( baseAddr + sizeof( mach_header_t ) );

	for( uint32_t i = 0; i < cmd_count; ++i )
	{
		if( seg->cmd == LC_SEGMENT_VALUE )
			lib.memorySize += seg->vmsize;

		seg = reinterpret_cast<segment_command_t *>( reinterpret_cast<uintptr_t>( seg ) + seg->cmdsize );
	}

#endif

	lib.baseAddress = reinterpret_cast<void *>( baseAddr );
	return true;
}
