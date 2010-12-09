/* vim:ts=8:sw=8:noet
 * elfrc.c - a resource compiler for ELF files
 * Copyright (C) 2006 Frerich Raabe <raabe@kde.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Useful reading:
 * - http://www.tachyonsoft.com/elf.pdf
 * - http://linux4u.jinr.ru/usoft/WWW/www_debian.org/Documentation/elf/elf.html
 */

#define ELFRC_COPYRIGHT "Copyright (C) 2006 Frerich Raabe <raabe@kde.org>"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

/* Unfortunately Linux only makes the generic ElfW(type) macro
 * public, all the other generics like ELF_CLASS or ELF_DATA
 * are private.
 */
#ifdef __Linux__
#  include <link.h>
#  ifndef ELF_CLASS
#    if __ELF_NATIVE_CLASS == 32
#      define ELF_CLASS ELFCLASS32
#    elif __ELF_NATIVE_CLASS == 64
#      define ELF_CLASS ELFCLASS64
#    endif
#  endif
#  ifndef ELF_DATA
#    if __BYTE_ORDER == __LITTLE_ENDIAN
#      define ELF_DATA ELFDATA2LSB
#    elif __BYTE_ORDER == __BIG_ENDIAN
#      define ELF_DATA ELFDATA2MSB
#    endif
#  endif
#  ifndef ELF_ST_INFO
#    define ELF_ST_INFO( type, bind ) (((type) << 4) + ((bind) & 0xf))
#  endif
#else
#  define ElfW(type) Elf_##type
#endif

struct Resource {
    enum { TEXT = 0, BINARY = 1 } type;
    char *symbol;
    unsigned int symbolSize;
    char *filename;
    unsigned int size;
    enum { FALSE = 0, TRUE = 1 } ignore;
    unsigned int payloadOffset;
    unsigned int strtabOffset;
    struct Resource *next;
} *resources = 0;

int verbosity = 0;

#define SECTIONHEADERCOUNT 9
#define TOTALHEADERSIZE ( sizeof( ElfW( Ehdr ) ) + \
                          sizeof( ElfW( Shdr ) ) * ( SECTIONHEADERCOUNT ) )

static const char commentData[] = "Created by elfrc "
                                  ELFRC_VERSION
                                  " "
                                  ELFRC_COPYRIGHT;
static const char shstrtabData[] =
    "\0"
    ".text\0"
    ".data\0"
    ".bss\0"
    ".rodata\0"
    ".comment\0"
    ".shstrtab\0"
    ".symtab\0"
    ".strtab";

static const ElfW(Sym) symtabData[] = {
    /* First symbol is the 'undefined' symbol */
    {
        0,                           /* Name (index into string table) */
        0,                        /* Symbol value */
        0,                        /* Size of associated object */
        ELF_ST_INFO( STB_LOCAL, STT_NOTYPE ),    /* Type and binding */
        STV_DEFAULT,                /* Visibility */
        STN_UNDEF                    /* Section index of symbol */
    },

    /* Symbol for the original file */
    {
        0,                        /* Name (index into string table) */
        0,                        /* Symbol value */
        0,                        /* Size of associated object */
        ELF_ST_INFO( STB_LOCAL, STT_FILE ),        /* Type and binding */
        STV_DEFAULT,                /* Visibility */
        SHN_ABS                    /* Section index of symbol */
    },

    /* Symbol for the .text section */
    {
        0,                        /* Name (index into string table) */
        0,                        /* Symbol value */
        0,                        /* Size of associated object */
        ELF_ST_INFO( STB_LOCAL, STT_SECTION ),    /* Type and binding */
        STV_DEFAULT,                /* Visibility */
        1                        /* Section index of symbol */
    },

    /* Symbol for the .data section */
    {
        0,                        /* Name (index into string table) */
        0,                        /* Symbol value */
        0,                        /* Size of associated object */
        ELF_ST_INFO( STB_LOCAL, STT_SECTION ),    /* Type and binding */
        STV_DEFAULT,                /* Visibility */
        2                        /* Section index of symbol */
    },

    /* Symbol for the .bss section */
    {
        0,                        /* Name (index into string table) */
        0,                        /* Symbol value */
        0,                        /* Size of associated object */
        ELF_ST_INFO( STB_LOCAL, STT_SECTION ),    /* Type and binding */
        STV_DEFAULT,                /* Visibility */
        3                        /* Section index of symbol */
    },

    /* Symbol for the .rodata section */
    {
        0,                        /* Name (index into string table) */
        0,                        /* Symbol value */
        0,                        /* Size of associated object */
        ELF_ST_INFO( STB_LOCAL, STT_SECTION ),    /* Type and binding */
        STV_DEFAULT,                /* Visibility */
        4                        /* Section index of symbol */
    },

    /* Symbol for the .comment section */
    {
        0,                        /* Name (index into string table) */
        0,                        /* Symbol value */
        0,                        /* Size of associated object */
        ELF_ST_INFO( STB_LOCAL, STT_SECTION ),    /* Type and binding */
        STV_DEFAULT,                /* Visibility */
        5                        /* Section index of symbol */
    }

    /* This array is extended with symbols for each resource. */
};

static ElfW(Ehdr) hdr = {
    { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
      ELF_CLASS,
      ELF_DATA,
      EV_CURRENT,
      0,                  /* PATCHED: OS ABI */
      0,
      0,
      0, 0, 0, 0, 0, 0 }, /* File identification */
    ET_REL,               /* File type */
    0,                    /* PATCHED: Machine architecture */
    1,                    /* ELF format version */
    0,                    /* Entry point */
    0,                    /* Program header file offset */
    sizeof( hdr ),        /* Section header file offset */
    0,                    /* PATCHED: Architecture-specific flags */
    sizeof( hdr ),        /* Size of this ELF header */
    0,                    /* Size of program header entry */
    0,                    /* Number of program header entries */
    sizeof( ElfW(Shdr) ), /* Size of section header entry */
    SECTIONHEADERCOUNT,   /* Number of section header entries */
    6                     /* Section name strings section */
};

static const ElfW(Shdr) nullHeader = {
    0,                /* Index into section header string table */
    SHT_NULL,            /* Section type */
    0,                /* Section flags */
    0,                /* Address in memory image */
    0,                /* Offset in file */
    0,                /* Size in bytes */
    0,                /* Index of a related section */
    0,                /* Depends on section type */
    0,                /* Alignment in bytes */
    0                /* Size of each entry in section */
};

static const ElfW(Shdr) textHeader = {
    1,                /* Index into section header string table */
    SHT_PROGBITS,            /* Section type */
    SHF_ALLOC | SHF_EXECINSTR,    /* Section flags */
    0,                /* Address in memory image */
    0,                /* Offset in file */
    0,                /* Size in bytes */
    0,                /* Index of a related section */
    0,                /* Depends on section type */
    4,                /* Alignment in bytes */
    0                /* Size of each entry in section */
};

static const ElfW(Shdr) dataHeader = {
    7,                /* Index into section header string table */
    SHT_PROGBITS,            /* Section type */
    SHF_ALLOC | SHF_WRITE,        /* Section flags */
    0,                /* Address in memory image */
    0,                /* Offset in file */
    0,                /* Size in bytes */
    0,                /* Index of a related section */
    0,                /* Depends on section type */
    4,                /* Alignment in bytes */
    0                /* Size of each entry in section */
};

static const ElfW(Shdr) bssHeader = {
    13,                /* Index into section header string table */
    SHT_NOBITS,            /* Section type */
    SHF_ALLOC | SHF_WRITE,        /* Section flags */
    0,                /* Address in memory image */
    0,                /* Offset in file */
    0,                /* Size in bytes */
    0,                /* Index of a related section */
    0,                /* Depends on section type */
    4,                /* Alignment in bytes */
    0                /* Size of each entry in section */
};

static ElfW(Shdr) rodataHeader = {
    18,                /* Index into section header string table */
    SHT_PROGBITS,            /* Section type */
    SHF_ALLOC,            /* Section flags */
    0,                /* Address in memory image */
    TOTALHEADERSIZE                 /* Offset in file */
    + sizeof( commentData )
    + sizeof( shstrtabData ),       /* PATCHED: + Symbol table size */
                    /*          + String table size */
    0,                /* PATCHED: Size in bytes */
    0,                /* Index of a related section */
    0,                /* Depends on section type */
    0,                /* PATCHED: Alignment in bytes */
    0                /* Size of each entry in section */
};

static ElfW(Shdr) commentHeader = {
    26,                /* Index into section header string table */
    SHT_PROGBITS,            /* Section type */
    0,                /* Section flags */
    0,                /* Address in memory image */
    TOTALHEADERSIZE,                /* Offset in file */
    sizeof( commentData ),        /* Size in bytes */
    0,                /* Index of a related section */
    0,                /* Depends on section type */
    1,                /* Alignment in bytes */
    0                /* Size of each entry in section */
};

static ElfW(Shdr) shstrtabHeader = {
    35,                /* Index into section header string table */
    SHT_STRTAB,            /* Section type */
    0,                /* Section flags */
    0,                /* Address in memory image */
    TOTALHEADERSIZE                 /* Offset in file */
    + sizeof( commentData ),
    sizeof( shstrtabData ),        /* Size in bytes */
    0,                /* Index of a related section */
    0,                /* Depends on section type */
    1,                /* Alignment in bytes */
    0                /* Size of each entry in section */
};

static ElfW(Shdr) symtabHeader = {
    45,                /* Index into section header string table */
    SHT_SYMTAB,            /* Section type */
    0,                /* Section flags */
    0,                /* Address in memory image */
    TOTALHEADERSIZE                 /* Offset in file */
    + sizeof( commentData )
    + sizeof( shstrtabData ),
    0,                /* PATCHED: Size in bytes */
    8,                /* Index of a related section */
    7,                /* Depends on section type */
    4,                /* Alignment in bytes */
    sizeof( symtabData[ 0 ] )    /* Size of each entry in section */
};

static ElfW(Shdr) strtabHeader = {
    53,                /* Index into section header string table */
    SHT_STRTAB,            /* Section type */
    0,                /* Section flags */
    0,                /* Address in memory image */
    TOTALHEADERSIZE                 /* Offset in file */
    + sizeof( commentData )
    + sizeof( shstrtabData ),
                    /* PATCHED: + symtabDataSize */
    0,                /* PATCHED: Size in bytes */
    0,                /* Index of a related section */
    0,                /* Depends on section type */
    1,                /* Alignment in bytes */
    0                /* Size of each entry in section */
};

static int copyFileToFD( const char *src, int dst )
{
    int fd;
    char buffer[ 8192 ];
    ssize_t nread;

    if ( verbosity > 0 )
        printf( "Merging %s into object file\n", src );

    if ( ( fd = open( src, O_RDONLY ) ) == -1 ) {
        fprintf( stderr, "Failed to open %s for reading: %s\n", src, strerror( errno ) );
        return -1;
    }

    do {
        if ( ( nread = read( fd, buffer,sizeof( buffer ) ) ) == -1 ) {
            fprintf( stderr, "Failed to read from %s: %s\n", src, strerror( errno ) );
            close( fd );
            return -1;
        }

        if ( write( dst, buffer, nread ) == -1 ) {
            close( fd );
            return -1;
        }
    } while ( nread == sizeof( buffer ) );

    return close( fd );
}

static unsigned int padding( unsigned int size )
{
    if ( size == rodataHeader.sh_addralign )
        return 0;
    return ( ( rodataHeader.sh_addralign - 1 ) & ( ~size ) ) + 1;
}

static int writeSymbols( int fd )
{
    struct Resource *it;
    ElfW(Sym) sym;

    for ( it = resources; it != 0; it = it->next ) {
        if ( it->ignore == TRUE )
            continue;

        /* Name (index into string table) */
        sym.st_name = it->strtabOffset;
        /* Symbol value (payload offset in section) */
        sym.st_value = it->payloadOffset;
        /* Payload size */
        sym.st_size = it->size;
        /* Type and binding (global object) */
        sym.st_info = ELF_ST_INFO( STB_GLOBAL, STT_OBJECT );
        /* Default visibility */
        sym.st_other = STV_DEFAULT;
        /* Payload section ( 4 == .rodata ) */
        sym.st_shndx = 4;

        if ( write( fd, &sym, sizeof( sym ) ) == -1 ) {
            fprintf( stderr, "Failed to write symbols: %s\n", strerror( errno ) );
            return -1;
        }
    }

    return 0;
}

static int writeStringTable( int fd )
{
    struct Resource *it;

    if ( write( fd, "\0", 1 ) == -1 ) {
        fprintf( stderr, "Failed to write string table: %s\n", strerror( errno ) );
        return -1;
    }

    for ( it = resources; it != 0; it = it->next ) {
        if ( it->ignore == TRUE )
            continue;
        if ( write( fd, it->symbol, it->symbolSize ) == -1 ) {
            fprintf( stderr, "Failed to write string table: %s\n", strerror( errno ) );
            return -1;
        }
    }

    return 0;
}

static int patchHeaders( const char *pathToSelf, ElfW(Ehdr) *archhdr )
{
    int maxalign = 1;
    int align;
    int payloadSize, symtabSize, strtabSize;
    struct Resource *it;
    ElfW(Ehdr) ownhdr;

    if (!archhdr) {
	/* If Architecture specific stuff is not given, we just take the values
	 * of our own elfrc binary. */

	int fd;

	/* Look into our own ELF header to determine the machine architecture .*/
	if ( ( fd = open( pathToSelf, O_RDONLY ) ) == -1 ) {
	    fprintf( stderr, "Failed to open %s for reading: %s\n", pathToSelf, strerror( errno ) );
	    return -1;
	}
	if ( read( fd, &ownhdr, sizeof( ownhdr ) ) == -1 ) {
	    fprintf( stderr, "Failed to read from %s: %s\n", pathToSelf, strerror( errno ) );
	    return -1;
	}
	close( fd );

	archhdr = &ownhdr;
    }
    hdr.e_machine = archhdr->e_machine;
    hdr.e_ident[EI_OSABI] = archhdr->e_ident[EI_OSABI];
    hdr.e_ident[EI_ABIVERSION] = archhdr->e_ident[EI_ABIVERSION];
    hdr.e_flags = archhdr->e_flags;

    /* Calculate alignment needed for .rodata */
    for ( it = resources; it != 0; it = it->next ) {
        align = 1;
        while ( align < sizeof(void *) * 8 && it->size > align )
            align <<= 1;
        if ( align > maxalign )
            maxalign = align;
    }

    /* Patch this first, since padding() depends on it. */
    rodataHeader.sh_addralign = maxalign;

    /* Compute size of payload, symbol table and string table.
       Also updates the cache fields it->payloadOffset and
       it->strtabOffset in the resource list. */
    payloadSize = 0;
    symtabSize = sizeof ( symtabData );
    strtabSize = 1;
    for ( it = resources; it != 0; it = it->next ) {
        it->payloadOffset = payloadSize;
        payloadSize += it->size;
        symtabSize += sizeof( symtabData[0] );
        it->strtabOffset = strtabSize;
        strtabSize += it->symbolSize;
        if ( it->next != 0 ) {
            payloadSize += padding( it->size );
        }
    }

    /* Patch the remaining headers. */
    rodataHeader.sh_size = payloadSize;
    rodataHeader.sh_offset += symtabSize + strtabSize;
    symtabHeader.sh_size = symtabSize;
    strtabHeader.sh_offset += symtabSize;
    strtabHeader.sh_size = strtabSize;

    return 0;
}

static int writeFiles( int fd )
{
    int i;
    int npad;
    struct Resource *it = resources;

    for ( it = resources; it != 0; it = it->next ) {
        if ( copyFileToFD( it->filename, fd ) == -1 ) {
            it->ignore = TRUE;
        } else {
            it->ignore = FALSE;

            /* Resources of type 'text' get a trailing
             * zero appended automatically. */
            if ( it->type == TEXT )
                write( fd, "\0", 1 );

            if ( it->next ) {
                /* Add padding bytes */
                npad = padding( it->size );
                for ( i = 0; i < npad; ++i )
                    write( fd, "\0", 1 );
            }
        }
    }

    return 0;
}

static int writeELFRelocatable( const char *fn )
{
    int fd;

    if ( !fn )
        return 0;

    if ( verbosity > 0 )
        printf( "Writing ELF relocatable file %s\n", fn );

    if ( ( fd = open( fn, O_WRONLY | O_CREAT | O_TRUNC, 0644) ) == -1 ) {
        fprintf( stderr, "Failed to open %s for writing: %s\n", fn, strerror( errno ) );
        return -1;
    }

#define WRITEBLOCK( b ) \
    if ( write( fd, &b, sizeof( b ) ) == -1 ) { \
        close( fd ); \
        return -1; \
    }

    WRITEBLOCK( hdr )

    WRITEBLOCK( nullHeader )
    WRITEBLOCK( textHeader )
    WRITEBLOCK( dataHeader )
    WRITEBLOCK( bssHeader )
    WRITEBLOCK( rodataHeader )
    WRITEBLOCK( commentHeader )
    WRITEBLOCK( shstrtabHeader )
    WRITEBLOCK( symtabHeader )
    WRITEBLOCK( strtabHeader )

    WRITEBLOCK( commentData )
    WRITEBLOCK( shstrtabData )

    WRITEBLOCK( symtabData )
    if ( writeSymbols( fd ) == -1 ) {
        close( fd );
        return -1;
    }

    if ( writeStringTable( fd ) == -1 ) {
        close( fd );
        return -1;
    }

    if ( writeFiles( fd ) == -1 ) {
        close( fd );
        return -1;
    }

#undef WRITEBLOCK

    if ( close( fd ) == -1 ) {
        fprintf( stderr, "Failed to close file %s: %s\n", fn, strerror( errno ) );
        return -1;
    }

    return 0;
}

static void registerResource( int type,
                              const char *symbol,
                              const char *fn,
                              unsigned int filesize )
{
    struct Resource *it = 0;
    struct Resource *res = (struct Resource *)malloc( sizeof( struct Resource ) );
    res->type = type;
    res->symbol = strdup( symbol );
    res->symbolSize = strlen( res->symbol ) + 1;
    res->filename = strdup( fn );
    res->size = filesize;
    if ( type == TEXT )
        ++res->size;
    res->next = 0;

    if ( !resources ) {
        resources = res;
    } else {
        for ( it = resources; it->next != 0; it = it->next )
            ;
        it->next = res;
    }

    if ( verbosity > 0 )
        printf( "Registered resurce %s (type %d) => %s (%d bytes)\n",
                symbol, type, fn, filesize );
}

static void freeResourceList()
{
    struct Resource *it = resources, *next;

    while ( it != 0 ) {
        free( it->symbol );
        free( it->filename );
        next = it->next;
        free( it );
        it = next;
    }
}

static int parseResourceFileData( const char *buffer, size_t len )
{
    static enum { ReadType, ReadSymbol, ReadFilename } state = ReadType;
    static char curType[ 32 ];
    static unsigned int curTypeLen = 0;
    static char curSymbol[ 256 ];
    static unsigned int curSymbolLen = 0;
    static char curFilename[ PATH_MAX ];
    static unsigned int curFilenameLen = 0;
    static unsigned int lineno;
    struct stat sb;
    const char *it;
    int type = 0;

    /* Signals 'EOF' */
    if ( !buffer ) {
        switch ( state ) {
        case ReadType:
            fprintf( stderr, "Error: Unexpected end of resource file; expected symbol name.\n" );
            return -1;
        case ReadSymbol:
            fprintf( stderr, "Error: Unexpected end of resource file; expected file name.\n" );
            return -1;
        case ReadFilename:
            curFilename[ curFilenameLen ] = '\0';

            if ( stat( curFilename, &sb ) == -1 ) {
                    fprintf( stderr, "Error in line %d of resource file: failed to access %s: %s\n",
                                    lineno, curFilename, strerror( errno ) );
                    return -1;
            }

            if ( strcmp( curType, "text") == 0 )
                    type = TEXT;
            else if ( strcmp( curType, "binary" ) == 0 )
                    type = BINARY;
            registerResource( type, curSymbol, curFilename, sb.st_size );
            return 0;
        }
    }

    for ( it = buffer; it < buffer + len; ++it ) {
        switch ( state ) {
        case ReadType:
            if ( *it == '\t' ) {
                curType[ curTypeLen ] = '\0';
                if ( strcmp( curType, "text" ) != 0 &&
                     strcmp( curType, "binary" ) != 0 ) {
                    fprintf( stderr,
                             "Warning: Unknown resource type '%s' in line %d of resource file; assuming 'binary'.\n",
                             curType, lineno  );
                    strncpy( curType, "binary", sizeof( curType ) );
                }
                state = ReadSymbol;
                curSymbolLen = 0;
            } else if ( *it == '\n' ) {
                fprintf( stderr,
                        "Error in line %d of resource file: expected tab and symbol name, got newline\n",
                        lineno );
                return -1;
            } else if ( curTypeLen < sizeof( curType ) ) {
                curType[ curTypeLen++ ] = *it;
            } else {
                    curType[ curTypeLen - 1 ] = '\0';
                fprintf( stderr,
                        "Error in line %d of resource file: resource type '%s' is too long\n",
                        lineno, curType );
                return -1;
            }
            break;
        case ReadSymbol:
            if ( *it == '\t' ) {
                curSymbol[ curSymbolLen ] = '\0';
                state = ReadFilename;
                curFilenameLen = 0;
            } else if ( *it == '\n' ) {
                fprintf( stderr,
                        "Error in line %d of resource file: expected tab and filename, got newline\n",
                        lineno );
                return -1;
            } else if ( curSymbolLen < sizeof( curSymbol ) ) {
                curSymbol[ curSymbolLen++ ] = *it;
            } else {
                curSymbol[ curSymbolLen - 1 ] = '\0';
                fprintf( stderr,
                        "Error in line %d of resource file: symbol '%s' is too long\n",
                        lineno, curSymbol );
                return -1;
            }
            break;
        case ReadFilename:
            if ( *it == '\n' ) {
                curFilename[ curFilenameLen ] = '\0';

                if ( stat( curFilename, &sb ) == -1 ) {
                    fprintf( stderr, "Error in line %d of resource file: failed to access %s: %s\n",
                             lineno, curFilename, strerror( errno ) );
                    return -1;
                }

                if ( strcmp( curType, "text") == 0 )
                    type = TEXT;
                else if ( strcmp( curType, "binary" ) == 0 )
                    type = BINARY;
                registerResource( type, curSymbol, curFilename, sb.st_size );

                state = ReadType;
                curTypeLen = 0;
                ++lineno;
            } else if ( curFilenameLen < sizeof( curFilename ) ) {
                curFilename[ curFilenameLen++ ] = *it;
            } else {
                curFilename[ curFilenameLen - 1 ] = '\0';
                fprintf( stderr,
                        "Error in line %d of resource file: file name '%s' is too long\n",
                        lineno, curFilename );
                return -1;
            }
            break;
        }
    }

    return 0;
}

static int loadResources( const char *fn )
{
    int fd;
    char buffer[ 1024 ];
    ssize_t nread;

    if ( verbosity > 0 )
        printf( "Loading resource configuration from %s\n", fn );

    if ( !fn || strcmp( fn, "-" ) == 0 ) {
        fd = STDIN_FILENO;
    } else if ( ( fd = open( fn, O_RDONLY ) ) == -1 ) {
        fprintf( stderr, "Failed to open %s for reading: %s\n", fn, strerror( errno ) );
        return -1;
    }

    do {
        if ( ( nread = read( fd, buffer, sizeof( buffer ) ) ) == -1 ) {
            fprintf( stderr, "Failed to read from %s: %s\n", fn, strerror( errno ) );
            close( fd );
            return -1;
        }

        if ( parseResourceFileData( buffer, nread ) == -1 ) {
            close( fd );
            return -1;
        }
    } while ( nread == sizeof( buffer ) );

    parseResourceFileData( 0, 0 );

    return close( fd );
}

static int writeCHeader( const char *fn )
{
    FILE *fd;
    struct Resource *it;
    char includeGuard[ 19 ];
    int i;

    if ( !fn )
        return 0;

    if ( verbosity > 0 )
        printf( "Writing header file %s\n", fn );

    if ( ( fd = fopen( fn, "w+" ) ) == NULL ) {
        fprintf( stderr, "Failed to open %s for writing: %s\n",
                 fn, strerror( errno ) );
        return -1;
    }

    /* Create a fancy include guard like 'H_2349823487234' */
    srand( time( NULL ) );
    includeGuard[0] = 'H';
    includeGuard[1] = '_';
    for ( i = 2; i < sizeof( includeGuard ) ; ++i )
        includeGuard[i] = '0' + rand() % 10;
    includeGuard[18] = '\0';

    /* Write include guard and C++ fixup out. */
    fprintf( fd,
             "#ifndef %s\n"
             "#define %s\n"
             "\n"
             "#ifdef __cplusplus\n"
             "extern \"C\" {\n"
             "#endif\n"
             "\n", includeGuard, includeGuard );

    fprintf( fd,
            "/* Automatically generated by elfrc " ELFRC_VERSION ". "
            "Do not modify by hand. */\n" );

    for ( it = resources; it != 0; it = it->next )
        fprintf( fd,
                 "\n"
                 "/* %s */\n"
                 "extern const char %s[%d];\n",
                 it->filename, it->symbol, it->size );

    /* Write include guard and C++ fixup out. */
    fprintf( fd,
             "\n"
             "#ifdef __cplusplus\n"
             "} /* extern \"C\" */\n"
             "#endif\n"
             "\n"
             "#endif /* %s */\n", includeGuard );

    return fclose( fd );
}

static void usage()
{
    printf( "elfrc " ELFRC_VERSION " - a resource compiler for ELF systems\n" );
    printf( ELFRC_COPYRIGHT "\n" );
    printf( "usage: elfrc [-o <filename>] [-h <filename>] [-v] [resfile]\n" );
}

static const char *findPathToSelf( const char *invocation )
{
    static char self[ PATH_MAX ];
    char *path, *it;
    struct stat sb;

    /* Invoked with absolute path, just use that. */
    if ( invocation[0] == '/' ) {
        strncpy( self, invocation, sizeof( self ) );
        return self;

    /* Invoked with relative path, append that to current working dir. */
    } else if ( strchr( invocation, '/' ) != NULL ) {
        getcwd( self, sizeof( self ) );
        strncat( self, "/", sizeof( self ) - strlen( self ) - 1 );
        strncat( self, invocation, sizeof( self ) - strlen( self ) - 1 );
        return self;

    /* Invoked with no path at all, scan through PATH to find us. */
    } else if ( ( path = getenv( "PATH" ) ) != NULL ) {
        for ( it = strtok( path, ":" ); it != NULL; it = strtok( NULL, ":" ) ) {
            snprintf( self, sizeof( self ), "%s/%s", it, invocation );
            if ( stat( self, &sb ) == -1 ) {
                continue;
            }

            if ( S_ISREG( sb.st_mode ) ) {
                return self;
            }
        }
    }

    return 0;
}

int main( int argc, char **argv )
{
    const char *invocation = argv[0];
    const char *pathToSelf = 0;
    char *objectOutput = 0;
    char *headerOutput = 0;
    signed char ch = 0;

    while ( ( ch = getopt( argc, argv, "o:h:v?" ) ) != -1 ) {
        switch( ch ) {
        case 'o':
            objectOutput = optarg;
            break;
        case 'h':
            headerOutput = optarg;
            break;
        case 'v':
            ++verbosity;
            break;
        case '?':
        default:
            usage();
            return 0;
        }
    }

    argc -= optind;
    argv += optind;

    if ( !objectOutput && !headerOutput ) {
        usage();
        printf( "No output chosen. Try -o and/or -h.\n" );
        return -1;
    }

    if ( ( pathToSelf = findPathToSelf( invocation ) ) == NULL ) {
        printf( "Failed to determine path to myself." );
        printf( "Try invoking with absolute path." );
        return -1;
    }

    if ( loadResources( argv[0] ) == -1 )
        return -1;

    if ( patchHeaders( pathToSelf, NULL ) == -1 )
        return -1;

    if ( writeELFRelocatable( objectOutput ) == -1 )
        return -1;

    if ( writeCHeader( headerOutput ) == -1 )
        return -1;

    freeResourceList();

    return 0;
}

