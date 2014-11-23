/*  PCSX2 - PS2 Emulator for PCs
 *  Copyright (C) 2002-2010  PCSX2 Dev Team
 *
 *  PCSX2 is free software: you can redistribute it and/or modify it under the terms
 *  of the GNU Lesser General Public License as published by the Free Software Found-
 *  ation, either version 3 of the License, or (at your option) any later version.
 *
 *  PCSX2 is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *  PURPOSE.  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with PCSX2.
 *  If not, see <http://www.gnu.org/licenses/>.
 */

#include "PrecompiledHeader.h"
#include "Utilities/SafeArray.inl"
#include <wx/file.h>
#include <wx/dir.h>

#include "MemoryCardFile.h"

// IMPORTANT!  If this gets a macro redefinition error it means PluginCallbacks.h is included
// in a global-scope header, and that's a BAD THING.  Include it only into modules that need
// it, because some need to be able to alter its behavior using defines.  Like this:

struct Component_FileMcd;
#define PS2E_THISPTR Component_FileMcd*

#include "System.h"
#include "AppConfig.h"

#include "svnrev.h"

#include <wx/ffile.h>
#include <map>

static const int MCD_SIZE	= 1024 *  8  * 16;		// Legacy PSX card default size

static const int MC2_MBSIZE	= 1024 * 528 * 2;		// Size of a single megabyte of card data
static const int MC2_SIZE	= MC2_MBSIZE * 8;		// PS2 card default size (8MB)

#pragma pack(push, 1)
// --------------------------------------------------------------------------------------
//  Currently Unused Superblock Header Struct
// --------------------------------------------------------------------------------------
// (provided for reference purposes)
struct superblock
{
	char magic[28]; 			// 0x00
	char version[12]; 			// 0x1c
	u16 page_len; 				// 0x28
	u16 pages_per_cluster;	 	// 0x2a
	u16 pages_per_block;		// 0x2c
	u16 unused; 				// 0x2e
	u32 clusters_per_card;	 	// 0x30
	u32 alloc_offset; 			// 0x34
	u32 alloc_end; 				// 0x38
	u32 rootdir_cluster;		// 0x3c
	u32 backup_block1;			// 0x40
	u32 backup_block2;			// 0x44
	u64 padding0x48;			// 0x48
	u32 ifc_list[32]; 			// 0x50
	u32 bad_block_list[32]; 	// 0xd0
	u8 card_type; 				// 0x150
	u8 card_flags; 				// 0x151
};
#pragma pack(pop)

// --------------------------------------------------------------------------------------
//  FileMemoryCard
// --------------------------------------------------------------------------------------
// Provides thread-safe direct file IO mapping.
//
class FileMemoryCard
{
protected:
	wxFFile			m_file[8];
	u8				m_effeffs[528*16];
	SafeArray<u8>	m_currentdata;
	u64				m_chksum[8];
	bool			m_ispsx[8];
	u32				m_chkaddr;

public:
	FileMemoryCard();
	virtual ~FileMemoryCard() throw() {}

	void Lock();
	void Unlock();

	void Open();
	void Close();

	s32  IsPresent	( uint slot );
	void GetSizeInfo( uint slot, PS2E_McdSizeInfo& outways );
	bool IsPSX	( uint slot );
	s32  Read		( uint slot, u8 *dest, u32 adr, int size );
	s32  Save		( uint slot, const u8 *src, u32 adr, int size );
	s32  EraseBlock	( uint slot, u32 adr );
	u64  GetCRC		( uint slot );

protected:
	bool Seek( wxFFile& f, u32 adr );
	bool Create( const wxString& mcdFile, uint sizeInMB );

	wxString GetDisabledMessage( uint slot ) const
	{
		return wxsFormat( pxE( L"The PS2-slot %d has been automatically disabled.  You can correct the problem\nand re-enable it at any time using Config:Memory cards from the main menu."
					) , slot//TODO: translate internal slot index to human-readable slot description
		);
	}
};

uint FileMcd_GetMtapPort(uint slot)
{
	switch( slot )
	{
		case 0: case 2: case 3: case 4: return 0;
		case 1: case 5: case 6: case 7: return 1;

		jNO_DEFAULT
	}

	return 0;		// technically unreachable.
}

// Returns the multitap slot number, range 1 to 3 (slot 0 refers to the standard
// 1st and 2nd player slots).
uint FileMcd_GetMtapSlot(uint slot)
{
	switch( slot )
	{
		case 0: case 1:
			pxFailDev( "Invalid parameter in call to GetMtapSlot -- specified slot is one of the base slots, not a Multitap slot." );
		break;

		case 2: case 3: case 4: return slot-1;
		case 5: case 6: case 7: return slot-4;

		jNO_DEFAULT
	}

	return 0;		// technically unreachable.
}

bool FileMcd_IsMultitapSlot( uint slot )
{
	return (slot > 1);
}
/*
wxFileName FileMcd_GetSimpleName(uint slot)
{
	if( FileMcd_IsMultitapSlot(slot) )
		return g_Conf->Folders.MemoryCards + wxsFormat( L"Mcd-Multitap%u-Slot%02u.ps2", FileMcd_GetMtapPort(slot)+1, FileMcd_GetMtapSlot(slot)+1 );
	else
		return g_Conf->Folders.MemoryCards + wxsFormat( L"Mcd%03u.ps2", slot+1 );
}
*/
wxString FileMcd_GetDefaultName(uint slot)
{
	if( FileMcd_IsMultitapSlot(slot) )
		return wxsFormat( L"Mcd-Multitap%u-Slot%02u.ps2", FileMcd_GetMtapPort(slot)+1, FileMcd_GetMtapSlot(slot)+1 );
	else
		return wxsFormat( L"Mcd%03u.ps2", slot+1 );
}

FileMemoryCard::FileMemoryCard()
{
	memset8<0xff>( m_effeffs );
}

void FileMemoryCard::Open()
{
	for( int slot=0; slot<8; ++slot )
	{
		if( FileMcd_IsMultitapSlot(slot) )
		{
			if( !EmuConfig.MultitapPort0_Enabled && (FileMcd_GetMtapPort(slot) == 0) ) continue;
			if( !EmuConfig.MultitapPort1_Enabled && (FileMcd_GetMtapPort(slot) == 1) ) continue;
		}

		wxFileName fname( g_Conf->FullpathToMcd( slot ) );
		wxString str( fname.GetFullPath() );
		bool cont = false;

		if( fname.GetFullName().IsEmpty() )
		{
			str = L"[empty filename]";
			cont = true;
		}

		if( !g_Conf->Mcd[slot].Enabled )
		{
			str = L"[disabled]";
			cont = true;
		}

		Console.WriteLn( cont ? Color_Gray : Color_Green, L"McdSlot %u: " + str, slot );
		if( cont ) continue;

		const wxULongLong fsz = fname.GetSize();
		if( (fsz == 0) || (fsz == wxInvalidSize) )
		{
			// FIXME : Ideally this should prompt the user for the size of the
			// memory card file they would like to create, instead of trying to
			// create one automatically.
		
			if( !Create( str, 8 ) )
			{
				Msgbox::Alert(
					wxsFormat(_( "Could not create a memory card: \n\n%s\n\n" ), str.c_str()) +
					GetDisabledMessage( slot )
				);
			}
		}

		// [TODO] : Add memcard size detection and report it to the console log.
		//   (8MB, 256Mb, formatted, unformatted, etc ...)

#ifdef __WXMSW__
		NTFS_CompressFile( str, g_Conf->McdCompressNTFS );
#endif

		if( !m_file[slot].Open( str.c_str(), L"r+b" ) )
		{
			// Translation note: detailed description should mention that the memory card will be disabled
			// for the duration of this session.
			Msgbox::Alert(
				wxsFormat(_( "Access denied to memory card: \n\n%s\n\n" ), str.c_str()) +
				GetDisabledMessage( slot )
			);
		}
		else // Load checksum
		{
			m_ispsx[slot] = m_file[slot].Length() == 0x20000;
			m_chkaddr = 0x210;

			if(!m_ispsx[slot] && !!m_file[slot].Seek( m_chkaddr ))
				m_file[slot].Read( &m_chksum[slot], 8 );
		}
	}
}

void FileMemoryCard::Close()
{
	for( int slot=0; slot<8; ++slot )
	{
		if (m_file[slot].IsOpened()) {
			// Store checksum
			if(!m_ispsx[slot] && !!m_file[slot].Seek(  m_chkaddr ))
				m_file[slot].Write( &m_chksum[slot], 8 );

			m_file[slot].Close();
		}
	}
}

// Returns FALSE if the seek failed (is outside the bounds of the file).
bool FileMemoryCard::Seek( wxFFile& f, u32 adr )
{
	const u32 size = f.Length();

	// If anyone knows why this filesize logic is here (it appears to be related to legacy PSX
	// cards, perhaps hacked support for some special emulator-specific memcard formats that
	// had header info?), then please replace this comment with something useful.  Thanks!  -- air

	u32 offset = 0;

	if( size == MCD_SIZE + 64 )
		offset = 64;
	else if( size == MCD_SIZE + 3904 )
		offset = 3904;
	else
	{
		// perform sanity checks here?
	}

	return f.Seek( adr + offset );
}

// returns FALSE if an error occurred (either permission denied or disk full)
bool FileMemoryCard::Create( const wxString& mcdFile, uint sizeInMB )
{
	//int enc[16] = {0x77,0x7f,0x7f,0x77,0x7f,0x7f,0x77,0x7f,0x7f,0x77,0x7f,0x7f,0,0,0,0};

	Console.WriteLn( L"(FileMcd) Creating new %uMB memory card: " + mcdFile, sizeInMB );

	wxFFile fp( mcdFile, L"wb" );
	if( !fp.IsOpened() ) return false;

	for( uint i=0; i<(MC2_MBSIZE*sizeInMB)/sizeof(m_effeffs); i++ )
	{
		if( fp.Write( m_effeffs, sizeof(m_effeffs) ) == 0 )
			return false;
	}
	return true;
}

s32 FileMemoryCard::IsPresent( uint slot )
{
	return m_file[slot].IsOpened();
}

void FileMemoryCard::GetSizeInfo( uint slot, PS2E_McdSizeInfo& outways )
{
	outways.SectorSize				= 512; // 0x0200
	outways.EraseBlockSizeInSectors	= 16;  // 0x0010
	outways.Xor						= 18;  // 0x12, XOR 02 00 00 10

	if( pxAssert( m_file[slot].IsOpened() ) )
		outways.McdSizeInSectors	= m_file[slot].Length() / (outways.SectorSize + outways.EraseBlockSizeInSectors);
	else
		outways.McdSizeInSectors	= 0x4000;

	u8 *pdata = (u8*)&outways.McdSizeInSectors;
	outways.Xor ^= pdata[0] ^ pdata[1] ^ pdata[2] ^ pdata[3];
}

bool FileMemoryCard::IsPSX( uint slot )
{
	return m_ispsx[slot];
}

s32 FileMemoryCard::Read( uint slot, u8 *dest, u32 adr, int size )
{
	wxFFile& mcfp( m_file[slot] );
	if( !mcfp.IsOpened() )
	{
		DevCon.Error( "(FileMcd) Ignoring attempted read from disabled slot." );
		memset(dest, 0, size);
		return 1;
	}

	const u32 block = adr / 0x2100u;
	const u32 page = adr / 0x210u;
	const u32 offset = adr % 0x210u;
	const u32 cluster = adr / 0x420u;
	const u32 end = offset + size;
	Console.WriteLn( L"(FileMcd) reading %03d bytes at %08x / block %04x, cluster %05x, page %05x, offset %03x", size, adr, block, cluster, page, offset );

	if( !Seek(mcfp, adr) ) return 0;
	if ( mcfp.Read( dest, size ) != 0 ) {
		Console.WriteLn( L"(FileMcd) %02x %02x %02x %02x  %02x %02x %02x %02x", dest[0], dest[1], dest[2], dest[3], dest[4], dest[5], dest[6], dest[7] );
		return 1;
	}
	return 0;
}

s32 FileMemoryCard::Save( uint slot, const u8 *src, u32 adr, int size )
{
	wxFFile& mcfp( m_file[slot] );

	if( !mcfp.IsOpened() )
	{
		DevCon.Error( "(FileMcd) Ignoring attempted save/write to disabled slot." );
		return 1;
	}

	const u32 block = adr / 0x2100u;
	const u32 page = adr / 0x210u;
	const u32 offset = adr % 0x210u;
	const u32 cluster = adr / 0x420u;
	const u32 end = offset + size;
	Console.WriteLn( L"(FileMcd) writing %03d bytes at %08x / block %04x, cluster %05x, page %05x, offset %03x", size, adr, block, cluster, page, offset );
	Console.WriteLn( L"(FileMcd) %02x %02x %02x %02x  %02x %02x %02x %02x", src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7] );

	if(m_ispsx[slot])
	{
		m_currentdata.MakeRoomFor( size );
		for (int i=0; i<size; i++) m_currentdata[i] = src[i];
	}
	else
	{
		if( !Seek(mcfp, adr) ) return 0;
		m_currentdata.MakeRoomFor( size );
		mcfp.Read( m_currentdata.GetPtr(), size);
		

		for (int i=0; i<size; i++)
		{
			if ((m_currentdata[i] & src[i]) != src[i])
				Console.Warning("(FileMcd) Warning: writing to uncleared data. (%d) [%08X]", slot, adr);
			m_currentdata[i] &= src[i];
		}

		// Checksumness
		{
			if(adr == m_chkaddr) 
				Console.Warning("(FileMcd) Warning: checksum sector overwritten. (%d)", slot);

			u64 *pdata = (u64*)&m_currentdata[0];
			u32 loops = size / 8;

			for(u32 i = 0; i < loops; i++)
				m_chksum[slot] ^= pdata[i];
		}
	}

	if( !Seek(mcfp, adr) ) return 0;
	return mcfp.Write( m_currentdata.GetPtr(), size ) != 0;
}

s32 FileMemoryCard::EraseBlock( uint slot, u32 adr )
{
	wxFFile& mcfp( m_file[slot] );

	if( !mcfp.IsOpened() )
	{
		DevCon.Error( "MemoryCard: Ignoring erase for disabled slot." );
		return 1;
	}

	const u32 block = adr / 0x2100u;
	Console.WriteLn( L"(FileMcd) erasing block at %08x / block %04x", adr, block );

	if( !Seek(mcfp, adr) ) return 0;
	return mcfp.Write( m_effeffs, sizeof(m_effeffs) ) != 0;
}

u64 FileMemoryCard::GetCRC( uint slot )
{
	wxFFile& mcfp( m_file[slot] );
	if( !mcfp.IsOpened() ) return 0;

	u64 retval = 0;

	if(m_ispsx[slot])
	{
		if( !Seek( mcfp, 0 ) ) return 0;

		// Process the file in 4k chunks.  Speeds things up significantly.
	
		u64 buffer[528*8];		// use 528 (sector size), ensures even divisibility
	
		const uint filesize = mcfp.Length() / sizeof(buffer);
		for( uint i=filesize; i; --i )
		{
			mcfp.Read( &buffer, sizeof(buffer) );
			for( uint t=0; t<ArraySize(buffer); ++t )
				retval ^= buffer[t];
		}
	}
	else
	{
		retval = m_chksum[slot];
	}

	return retval;
}

#pragma pack(push, 1)
// --------------------------------------------------------------------------------------
//  MemoryCardFileEntry
// --------------------------------------------------------------------------------------
// Structure for directory and file relationships as stored on memory cards
struct MemoryCardFileEntry {
	union {
		struct MemoryCardFileEntryData {
			u32 mode;
			u32 length; // number of bytes for file, number of files for dir
			u64 timeCreated;
			u32 cluster; // cluster the start of referred file or folder can be found in
			u32 dirEntry; // parent directory entry number, only used if "." entry of subdir
			u64 timeModified;
			u32 attr;
			u8 padding[0x1C];
			u8 name[0x20];
			u8 unused[0x1A0];
		} data;
		u8 raw[0x200];
	} entry;

	bool IsFile() { return !!( entry.data.mode & 0x0010 ); }
	bool IsDir()  { return !!( entry.data.mode & 0x0020 ); }
	bool IsUsed() { return !!( entry.data.mode & 0x8000 ); }
};
#pragma pack(pop)

struct MemoryCardFileEntryCluster {
	MemoryCardFileEntry entries[2];
};

// --------------------------------------------------------------------------------------
//  FolderMemoryCard
// --------------------------------------------------------------------------------------
// Fakes a memory card using a regular folder/file structure in the host file system
class FolderMemoryCard
{
protected:
	wxFileName folderName;

	static const int IndirectFatClusterCount = 1; // should be 32 but only 1 is ever used
	static const int ClusterSize = 0x400;

	union superBlockUnion {
		superblock data;
		u8 raw[0x2000];
	} superBlock;
	union indirectFatUnion {
		u32 data[IndirectFatClusterCount][ClusterSize / 4];
		u8 raw[IndirectFatClusterCount][ClusterSize];
	} m_indirectFat;
	union fatUnion {
		u32 data[IndirectFatClusterCount][ClusterSize / 4][ClusterSize / 4];
		u8 raw[IndirectFatClusterCount][ClusterSize / 4][ClusterSize];
	} m_fat;
	u8 m_backupBlock1[0x2000];
	u8 m_backupBlock2[0x2000];

	std::map<u32, MemoryCardFileEntryCluster> m_fileEntryDict;

	uint slot;
	bool formatted = false;
	bool duringFormatting = false;
	u8 m_fakeFormattingData = 0xFF;

public:
	FolderMemoryCard();
	virtual ~FolderMemoryCard() throw() {}

	void Lock();
	void Unlock();

	void Open();
	void Close();

	s32  IsPresent();
	void GetSizeInfo(PS2E_McdSizeInfo& outways);
	bool IsPSX();
	s32  Read(u8 *dest, u32 adr, int size);
	s32  Save(const u8 *src, u32 adr, int size);
	s32  EraseBlock(u32 adr);
	u64  GetCRC();

	void SetSlot(uint slot);

	static void CalculateECC( u8* ecc, const u8* data );

protected:
	// initializes memory card data, as if it was fresh from the factory
	void InitializeInternalData();


	// returns the in-memory address of data the given memory card adr corresponds to
	// returns nullptr if adr corresponds to a folder or file entry
	u8* GetSystemBlockPointer( const u32 adr );
	
	// returns in-memory address of file or directory metadata searchCluster corresponds to
	// returns nullptr if searchCluster contains something else
	// originally call by passing:
	// - currentCluster: the root directory cluster as indicated in the superblock
	// - searchCluster: the cluster that is being accessed, relative to alloc_offset in the superblock
	// - entryNumber: page of cluster
	// - offset: offset of page
	u8* GetFileEntryPointer( const u32 currentCluster, const u32 searchCluster, const u32 entryNumber, const u32 offset );
	
	// returns file entry of the file at the given searchCluster
	// the passed fileName will be filled with a path to the file being accessed
	// returns nullptr if searchCluster contains no file
	// call by passing:
	// - currentCluster: the root directory cluster as indicated in the superblock
	// - searchCluster: the cluster that is being accessed, relative to alloc_offset in the superblock
	// - fileName: wxFileName of the root directory of the memory card folder in the host file system (filename part doesn't matter)
	// - originalDirCount: the point in fileName where to insert the found folder path, usually fileName->GetDirCount()
	// - outClusterNumber: the cluster's sequential number of the file will be written to this pointer,
	//                     which can be used to calculate the in-file offset of the address being accessed
	MemoryCardFileEntry* FolderMemoryCard::GetFileEntryFromFileDataCluster( const u32 currentCluster, const u32 searchCluster, wxFileName* fileName, const size_t originalDirCount, u32* outClusterNumber );


	// loads files and folders from the host file system if a superblock exists in the root directory
	void LoadMemoryCardData();

	// creates the FAT and indirect FAT
	void CreateFat();

	// creates file entries for the root directory
	void CreateRootDir();
	

	// returns the system cluster past the highest used one (will be the lowest free one under normal use)
	// this is used for creating the FAT, don't call otherwise unless you know exactly what you're doing
	u32 GetFreeSystemCluster();

	// returns the lowest unused data cluster, relative to alloc_offset in the superblock
	u32 GetFreeDataCluster();

	// returns the final cluster of the file or directory which is (partially) stored in the given cluster
	u32 GetLastClusterOfData( const u32 cluster );


	// creates and returns a new file entry in the given directory entry, ready to be filled
	MemoryCardFileEntry* AppendFileEntryToDir( MemoryCardFileEntry* const dirEntry );

	// adds a folder in the host file system to the memory card, including all files and subdirectories
	// - dirEntry: the entry of the directory in the parent directory, or the root "." entry
	// - dirPath: the full path to the directory in the host file system
	void AddFolder( MemoryCardFileEntry* const dirEntry, const wxString& dirPath );

	// adds a file in the host file sytem to the memory card
	// - dirEntry: the entry of the directory in the parent directory, or the root "." entry
	// - dirPath: the full path to the directory containing the file in the host file system
	// - fileName: the name of the file, without path
	void AddFile( MemoryCardFileEntry* const dirEntry, const wxString& dirPath, const wxString& fileName );


	bool ReadFromFile( u8 *dest, u32 adr, u32 dataLength );
	bool WriteToFile( const u8* src, u32 adr, u32 dataLength );

	wxString GetDisabledMessage(uint slot) const
	{
		return wxsFormat(pxE(L"The PS2-slot %d has been automatically disabled.  You can correct the problem\nand re-enable it at any time using Config:Memory cards from the main menu."
			), slot//TODO: translate internal slot index to human-readable slot description
			);
	}
};

FolderMemoryCard::FolderMemoryCard()
{
	slot = 0;
}

void FolderMemoryCard::InitializeInternalData() {
	memset( &superBlock, 0xFF, sizeof( superBlock ) );
	memset( &m_indirectFat, 0xFF, sizeof( m_indirectFat ) );
	memset( &m_fat, 0xFF, sizeof( m_fat ) );
	memset( &m_backupBlock1, 0xFF, sizeof( m_backupBlock1 ) );
	memset( &m_backupBlock2, 0xFF, sizeof( m_backupBlock2 ) );
	formatted = false;
	duringFormatting = false;
	m_fakeFormattingData = 0xFF;
}

void FolderMemoryCard::Open()
{
	InitializeInternalData();

	wxFileName configuredFileName( g_Conf->FullpathToMcd(slot) );
	configuredFileName.ClearExt();
	folderName = wxFileName( configuredFileName.GetFullPath() + L"/" );
	wxString str( configuredFileName.GetFullPath() );
	bool disabled = false;

	if ( g_Conf->Mcd[slot].Enabled ) {
		if ( configuredFileName.GetFullName().IsEmpty() ) {
			str = L"[empty filename]";
			disabled = true;
		}
		if ( !disabled && configuredFileName.FileExists() ) {
			str = L"[is file, should be folder]";
			disabled = true;
		}
		
		// if nothing exists at a valid location, create a directory for the memory card
		if ( !disabled && !folderName.DirExists() ) {
			if ( !folderName.Mkdir() ) {
				str = L"[couldn't create folder]";
				disabled = true;
			}
		}
	} else {
		str = L"[disabled]";
		disabled = true;
	}

	Console.WriteLn( disabled ? Color_Gray : Color_Green, L"McdSlot %u: " + str, slot );
	if ( disabled ) return;

	LoadMemoryCardData();
}

void FolderMemoryCard::Close() {
	if ( formatted && !duringFormatting ) {
		wxFileName superBlockFileName( folderName.GetPath(), L"_pcsx2_superblock" );
		wxFFile superBlockFile( superBlockFileName.GetFullPath().c_str(), L"w" );
		if ( superBlockFile.IsOpened() ) {
			superBlockFile.Write( &superBlock.raw, sizeof( superBlock.raw ) );
		}
	}
}

void FolderMemoryCard::LoadMemoryCardData() {
	formatted = false;

	// read superblock if it exists
	wxFileName superBlockFileName( folderName.GetPath(), L"_pcsx2_superblock" );
	if ( superBlockFileName.FileExists() ) {
		wxFFile superBlockFile( superBlockFileName.GetFullPath().c_str(), L"r" );
		if ( superBlockFile.IsOpened() && superBlockFile.Read( &superBlock.raw, sizeof( superBlock.raw ) ) >= sizeof( superBlock.data ) ) {
			if ( superBlock.raw[0x16] == 0x6F ) {
				formatted = true;
			}
		}
	}

	// if superblock was valid, load folders and files
	if ( formatted ) {
		CreateFat();
		CreateRootDir();
		MemoryCardFileEntry* const rootDirEntry = &m_fileEntryDict[superBlock.data.rootdir_cluster].entries[0];
		AddFolder( rootDirEntry, folderName.GetPath() );
	}

	return;
}

void FolderMemoryCard::CreateFat() {
	const u32 totalClusters = superBlock.data.clusters_per_card;
	const u32 clusterSize = superBlock.data.page_len * superBlock.data.pages_per_cluster;
	const u32 fatEntriesPerCluster = clusterSize / 4;
	const u32 countFatClusters = ( totalClusters % fatEntriesPerCluster ) != 0 ? ( totalClusters / fatEntriesPerCluster + 1 ) : ( totalClusters / fatEntriesPerCluster );
	const u32 countDataClusters = superBlock.data.alloc_end;

	// create indirect FAT
	for ( unsigned int i = 0; i < countFatClusters; ++i ) {
		m_indirectFat.data[0][i] = GetFreeSystemCluster();
	}

	// fill FAT with default values
	for ( unsigned int i = 0; i < countDataClusters; ++i ) {
		m_fat.data[0][0][i] = 0x7FFFFFFFu;
	}
}

void FolderMemoryCard::CreateRootDir() {
	MemoryCardFileEntryCluster* const rootCluster = &m_fileEntryDict[superBlock.data.rootdir_cluster];
	memset( &rootCluster->entries[0].entry.raw[0], 0x00, 0x200 );
	rootCluster->entries[0].entry.data.mode = 0x8427;
	rootCluster->entries[0].entry.data.length = 2;
	rootCluster->entries[0].entry.data.name[0] = '.';

	memset( &rootCluster->entries[1].entry.raw[0], 0x00, 0x200 );
	rootCluster->entries[1].entry.data.mode = 0xA426;
	rootCluster->entries[1].entry.data.name[0] = '.';
	rootCluster->entries[1].entry.data.name[1] = '.';

	// mark root dir cluster as used
	m_fat.data[0][0][superBlock.data.rootdir_cluster] = 0xFFFFFFFFu;
}

u32 FolderMemoryCard::GetFreeSystemCluster() {
	// first block is reserved for superblock
	u32 highestUsedCluster = ( superBlock.data.pages_per_block / superBlock.data.pages_per_cluster ) - 1;

	// can't use any of the indirect fat clusters
	for ( int i = 0; i < IndirectFatClusterCount; ++i ) {
		highestUsedCluster = std::max( highestUsedCluster, superBlock.data.ifc_list[i] );
	}

	// or fat clusters
	for ( int i = 0; i < IndirectFatClusterCount; ++i ) {
		for ( int j = 0; j < ClusterSize / 4; ++j ) {
			if ( m_indirectFat.data[i][j] != 0xFFFFFFFFu ) {
				highestUsedCluster = std::max( highestUsedCluster, m_indirectFat.data[i][j] );
			}
		}
	}

	return highestUsedCluster + 1;
}

u32 FolderMemoryCard::GetFreeDataCluster() {
	const u32 countDataClusters = superBlock.data.alloc_end;

	for ( unsigned int i = 0; i < countDataClusters; ++i ) {
		const u32 cluster = m_fat.data[0][0][i];

		if ( ( cluster & 0x80000000 ) == 0 ) {
			return i;
		}
	}

	return 0xFFFFFFFF;
}

u32 FolderMemoryCard::GetLastClusterOfData( const u32 cluster ) {
	u32 entryCluster;
	u32 nextCluster = cluster;
	do {
		entryCluster = nextCluster;
		nextCluster = m_fat.data[0][0][entryCluster] & 0x7FFFFFFF;
	} while ( nextCluster != 0x7FFFFFFF );
	return entryCluster;
}

MemoryCardFileEntry* FolderMemoryCard::AppendFileEntryToDir( MemoryCardFileEntry* const dirEntry ) {
	u32 entryCluster = GetLastClusterOfData( dirEntry->entry.data.cluster );

	MemoryCardFileEntry* newFileEntry;
	if ( dirEntry->entry.data.length % 2 == 0 ) {
		// need new cluster
		u32 newCluster = GetFreeDataCluster();
		m_fat.data[0][0][entryCluster] = newCluster | 0x80000000;
		m_fat.data[0][0][newCluster] = 0xFFFFFFFF;
		newFileEntry = &m_fileEntryDict[newCluster].entries[0];
	} else {
		// can use last page of existing clusters
		newFileEntry = &m_fileEntryDict[entryCluster].entries[1];
	}

	return newFileEntry;
}

void FolderMemoryCard::AddFolder( MemoryCardFileEntry* const dirEntry, const wxString& dirPath ) {
	wxDir dir( dirPath );
	if ( dir.IsOpened() ) {
		Console.WriteLn( L"(FolderMcd) Adding folder: %s", dirPath.c_str() );
		
		const u32 dirStartCluster = dirEntry->entry.data.cluster;

		wxString fileName;
		bool hasNext;

		int entryNumber = 2; // include . and ..
		hasNext = dir.GetFirst( &fileName );
		while ( hasNext ) {
			bool isFile = wxFile::Exists( wxFileName( dirPath, fileName ).GetFullPath() );

			if ( isFile ) {
				if ( !fileName.StartsWith( L"_pcsx2_" ) ) {
					AddFile( dirEntry, dirPath, fileName );
					++entryNumber;
				}
			} else {
				// is a subdirectory
				// add entry for subdir in parent dir
				MemoryCardFileEntry* newDirEntry = AppendFileEntryToDir( dirEntry );
				dirEntry->entry.data.length++;
				newDirEntry->entry.data.mode = 0x8427;
				newDirEntry->entry.data.length = 2;
				strcpy( (char*)&newDirEntry->entry.data.name[0], fileName.mbc_str() );

				// create new cluster for . and .. entries
				u32 newCluster = GetFreeDataCluster();
				m_fat.data[0][0][newCluster] = 0xFFFFFFFF;
				newDirEntry->entry.data.cluster = newCluster;

				MemoryCardFileEntryCluster* const subDirCluster = &m_fileEntryDict[newCluster];
				memset( &subDirCluster->entries[0].entry.raw[0], 0x00, 0x200 );
				subDirCluster->entries[0].entry.data.mode = 0x8427;
				subDirCluster->entries[0].entry.data.dirEntry = entryNumber;
				subDirCluster->entries[0].entry.data.name[0] = '.';

				memset( &subDirCluster->entries[1].entry.raw[0], 0x00, 0x200 );
				subDirCluster->entries[1].entry.data.mode = 0x8427;
				subDirCluster->entries[1].entry.data.name[0] = '.';
				subDirCluster->entries[1].entry.data.name[1] = '.';

				// and add all files in subdir
				AddFolder( newDirEntry, wxFileName( dirPath, fileName ).GetFullPath() );
				++entryNumber;
			}

			hasNext = dir.GetNext( &fileName );
		}
	}
}

void FolderMemoryCard::AddFile( MemoryCardFileEntry* const dirEntry, const wxString& dirPath, const wxString& fileName ) {
	wxFileName relativeFilePath( dirPath, fileName );
	relativeFilePath.MakeRelativeTo( folderName.GetPath() );
	Console.WriteLn( L"(FolderMcd) Adding file: %s", relativeFilePath.GetFullPath().c_str() );

	MemoryCardFileEntry* newFileEntry = AppendFileEntryToDir( dirEntry );

	wxFFile file( wxFileName( dirPath, fileName ).GetFullPath(), L"r" );
	if ( file.IsOpened() ) {
		// set file entry data
		const u32 filesize = file.Length();
		memset( &newFileEntry->entry.raw[0], 0x00, 0x200 );
		newFileEntry->entry.data.mode = 0x8497;
		newFileEntry->entry.data.length = filesize;
		u32 fileDataStartingCluster = GetFreeDataCluster();
		newFileEntry->entry.data.cluster = fileDataStartingCluster;
		strcpy( (char*)&newFileEntry->entry.data.name[0], fileName.mbc_str() );

		// mark the appropriate amount of clusters as used
		const u32 clusterSize = superBlock.data.pages_per_cluster * superBlock.data.page_len;
		const u32 countClusters = ( filesize % clusterSize ) != 0 ? ( filesize / clusterSize + 1 ) : ( filesize / clusterSize );

		u32 dataCluster = fileDataStartingCluster;
		m_fat.data[0][0][dataCluster] = 0xFFFFFFFF;
		for ( unsigned int i = 0; i < countClusters - 1; ++i ) {
			u32 newCluster = GetFreeDataCluster();
			m_fat.data[0][0][dataCluster] = newCluster | 0x80000000;
			m_fat.data[0][0][newCluster] = 0xFFFFFFFF;
			dataCluster = newCluster;
		}

		file.Close();
	}

	// and finally, increase file count in the directory entry
	dirEntry->entry.data.length++;
}

s32 FolderMemoryCard::IsPresent()
{
	return folderName.DirExists();
}

void FolderMemoryCard::GetSizeInfo(PS2E_McdSizeInfo& outways)
{
	if ( formatted ) {
		outways.SectorSize = superBlock.data.page_len;
		outways.EraseBlockSizeInSectors = superBlock.data.pages_per_block;
		outways.McdSizeInSectors = superBlock.data.clusters_per_card * superBlock.data.pages_per_cluster;
	} else {
		outways.SectorSize = 512;
		outways.EraseBlockSizeInSectors = 16;
		outways.McdSizeInSectors = 0x4000;
	}

	u8 *pdata = (u8*)&outways.McdSizeInSectors;
	outways.Xor = 18;
	outways.Xor ^= pdata[0] ^ pdata[1] ^ pdata[2] ^ pdata[3];
}

bool FolderMemoryCard::IsPSX()
{
	// TODO: Implement
	return false;
}

u8* FolderMemoryCard::GetSystemBlockPointer( const u32 adr ) {
	const u32 block = adr / 0x2100u;
	const u32 page = adr / 0x210u;
	const u32 offset = adr % 0x210u;
	const u32 cluster = adr / 0x420u;

	const u32 startDataCluster = superBlock.data.alloc_offset;
	const u32 endDataCluster = startDataCluster + superBlock.data.alloc_end;
	if ( formatted && cluster >= startDataCluster && cluster < endDataCluster ) {
		// trying to access a file entry?
		const u32 fatCluster = cluster - superBlock.data.alloc_offset;
		return GetFileEntryPointer( superBlock.data.rootdir_cluster, fatCluster, page % 2, offset );
	}

	u8* src = nullptr;
	if ( block == 0 ) {
		src = &superBlock.raw[page * 0x200u + offset];
	} else if ( formatted && block == superBlock.data.backup_block1 ) {
		src = &m_backupBlock1[( page % 16 ) * 0x200u + offset];
	} else if ( formatted && block == superBlock.data.backup_block2 ) {
		src = &m_backupBlock2[( page % 16 ) * 0x200u + offset];
	} else if ( formatted ) {
		// trying to access indirect FAT?
		for ( int i = 0; i < IndirectFatClusterCount; ++i ) {
			if ( cluster == superBlock.data.ifc_list[i] ) {
				src = &m_indirectFat.raw[i][( page % 2 ) * 0x200u + offset];
				return src;
			}
		}
		// trying to access FAT?
		for ( int i = 0; i < IndirectFatClusterCount; ++i ) {
			for ( int j = 0; j < ClusterSize / 4; ++j ) {
				const u32 fatCluster = m_indirectFat.data[i][j];
				if ( fatCluster != 0xFFFFFFFFu && fatCluster == cluster ) {
					src = &m_fat.raw[i][j][( page % 2 ) * 0x200u + offset];
					return src;
				}
			}
		}
	}

	return src;
}

u8* FolderMemoryCard::GetFileEntryPointer( const u32 currentCluster, const u32 searchCluster, const u32 entryNumber, const u32 offset ) {
	// we found the correct cluster, return pointer to it
	if ( currentCluster == searchCluster ) {
		return &m_fileEntryDict[currentCluster].entries[entryNumber].entry.raw[offset];
	}

	// check other clusters of this directory
	const u32 nextCluster = m_fat.data[0][0][currentCluster] & 0x7FFFFFFF;
	if ( nextCluster != 0x7FFFFFFF ) {
		u8* ptr = GetFileEntryPointer( nextCluster, searchCluster, entryNumber, offset );
		if ( ptr != nullptr ) { return ptr; }
	}

	// check subdirectories
	for ( int i = 0; i < 2; ++i ) {
		MemoryCardFileEntry* const entry = &m_fileEntryDict[currentCluster].entries[i];
		if ( entry->IsUsed() && entry->IsDir() && entry->entry.data.cluster != 0 ) {
			u8* ptr = GetFileEntryPointer( entry->entry.data.cluster, searchCluster, entryNumber, offset );
			if ( ptr != nullptr ) { return ptr; }
		}
	}

	return nullptr;
}

MemoryCardFileEntry* FolderMemoryCard::GetFileEntryFromFileDataCluster( const u32 currentCluster, const u32 searchCluster, wxFileName* fileName, const size_t originalDirCount, u32* outClusterNumber ) {
	// check both entries of the current cluster if they're the file we're searching for, and if yes return it
	for ( int i = 0; i < 2; ++i ) {
		MemoryCardFileEntry* const entry = &m_fileEntryDict[currentCluster].entries[i];
		if ( entry->IsUsed() && entry->IsFile() ) {
			u32 fileCluster = entry->entry.data.cluster;
			u32 clusterNumber = 0;
			do {
				if ( fileCluster == searchCluster ) {
					fileName->SetName( wxString::FromAscii( (const char*)entry->entry.data.name ) );
					*outClusterNumber = clusterNumber;
					return entry;
				}
				++clusterNumber;
			} while ( ( fileCluster = m_fat.data[0][0][fileCluster] & 0x7FFFFFFF ) != 0x7FFFFFFF );
			// There's a lot of optimization work that can be done here, looping through all clusters of every single file
			// is not very efficient, especially since files are going to be accessed from the start and in-order the vast
			// majority of the time. You can probably cut a lot of the work by remembering the state of the last access
			// and only checking if the current access is either the same or the next cluster according to the FAT.
			//} while ( false );
		}
	}

	// check other clusters of this directory
	// this can probably be solved more efficiently by looping through nextClusters instead of recursively calling
	const u32 nextCluster = m_fat.data[0][0][currentCluster] & 0x7FFFFFFF;
	if ( nextCluster != 0x7FFFFFFF ) {
		MemoryCardFileEntry* ptr = GetFileEntryFromFileDataCluster( nextCluster, searchCluster, fileName, originalDirCount, outClusterNumber );
		if ( ptr != nullptr ) { return ptr; }
	}

	// check subdirectories
	for ( int i = 0; i < 2; ++i ) {
		MemoryCardFileEntry* const entry = &m_fileEntryDict[currentCluster].entries[i];
		if ( entry->IsUsed() && entry->IsDir() && entry->entry.data.cluster != 0 ) {
			MemoryCardFileEntry* ptr = GetFileEntryFromFileDataCluster( entry->entry.data.cluster, searchCluster, fileName, originalDirCount, outClusterNumber );
			if ( ptr != nullptr ) {
				fileName->InsertDir( originalDirCount, wxString::FromAscii( (const char*)entry->entry.data.name ) );
				return ptr;
			}
		}
	}

	return nullptr;
}

bool FolderMemoryCard::ReadFromFile( u8 *dest, u32 adr, u32 dataLength ) {
	const u32 page = adr / 0x210u;
	const u32 offset = adr % 0x210u;
	const u32 cluster = adr / 0x420u;
	const u32 fatCluster = cluster - superBlock.data.alloc_offset;

	// figure out which file to read from
	wxFileName fileName( folderName );
	u32 clusterNumber;
	const MemoryCardFileEntry* const entry = GetFileEntryFromFileDataCluster( superBlock.data.rootdir_cluster, fatCluster, &fileName, fileName.GetDirCount(), &clusterNumber );
	if ( entry != nullptr ) {
		Console.WriteLn( L"(FolderMcd) Reading from %s", fileName.GetFullPath().c_str() );
		if ( !fileName.DirExists() ) {
			fileName.Mkdir();
		}
		wxFFile file( fileName.GetFullPath(), L"rb" );
		if ( file.IsOpened() ) {
			const u32 clusterOffset = ( page % 2 ) * 0x200u + offset;
			const u32 fileOffset = clusterNumber * 0x400u + clusterOffset;
			Console.WriteLn( L"(FolderMcd) Reading %03d bytes at %08x, corresponds to cluster %d offset %03x or file offset %06x", dataLength, adr, clusterNumber, clusterOffset, fileOffset );

			file.Seek( fileOffset );
			size_t bytesRead = file.Read( dest, dataLength );

			// if more bytes were requested than actually exist, fill the rest with 0xFF
			if ( bytesRead < dataLength ) {
				memset( &dest[bytesRead], 0xFF, dataLength - bytesRead );
			}

			file.Close();

			return bytesRead > 0;
		}
	} else {
		Console.WriteLn( L"(FolderMcd) Reading nothing???" );
	}

	return false;
}

s32 FolderMemoryCard::Read(u8 *dest, u32 adr, int size)
{
	const u32 block = adr / 0x2100u;
	const u32 page = adr / 0x210u;
	const u32 offset = adr % 0x210u;
	const u32 cluster = adr / 0x420u;
	const u32 end = offset + size;
	Console.WriteLn( L"(FolderMcd) reading %03d bytes at %08x / block %04x, cluster %05x, page %05x, offset %03x", size, adr, block, cluster, page, offset );

	if ( duringFormatting ) {
		// fake all access
		if ( end > 0x200 && m_fakeFormattingData == 0x00 ) {
			// is reading ECC, give the accurate one for all zeroes
			for ( int i = 0; i < 12; i += 3 ) {
				dest[i] = 0x77; dest[i + 1] = 0x7f; dest[i + 2] = 0x7f;
			}
			for ( int i = 12; i < 16; ++i ) {
				dest[i] = 0x00;
			}
		} else {
			// just return the last fake byte written
			memset( dest, m_fakeFormattingData, size );
		}
		return 1;
	}

	if ( !formatted && block > 0 ) {
		memset( dest, 0xFF, size );
		Console.WriteLn( L"(FolderMcd) reading from unformatted memory card, returning 0xFFs" );
		return 1;
	}

	if ( end > 0x210 ) {
		// is trying to read more than one page at a time
		// do this recursively so that each function call only has to care about one page
		const u32 toNextPage = 0x210u - offset;
		Read( dest + toNextPage, adr + toNextPage, size - toNextPage );
		size = toNextPage;
	}

	if ( offset < 0x200 ) {
		// is trying to read (part of) an actual data block
		const u32 dataOffset = 0;
		const u32 dataLength = std::min( (u32)size, 0x200u - offset );

		u8* src = GetSystemBlockPointer( adr );
		if ( src != nullptr ) {
			memcpy( dest, src, dataLength );
			Console.WriteLn( L"(FolderMcd) %02x %02x %02x %02x  %02x %02x %02x %02x", src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7] );
		} else {
			if ( !ReadFromFile( dest, adr, dataLength ) ) {
				memset( dest, 0xFF, dataLength );
			}
		}
	}

	if ( end > 0x200 ) {
		// is trying to (partially) read the ECC
		const u32 eccOffset = 0x200u - offset;
		const u32 eccLength = std::min( size - offset, 0x10u );
		const u32 adrStart = page * 0x210u;
		
		u8 data[0x200];
		u8* src = GetSystemBlockPointer( adrStart );
		if ( src != nullptr ) {
			memcpy( data, src, 0x200 );
		} else {
			if ( !ReadFromFile( data, adrStart, 0x200 ) ) {
				memset( data, 0xFF, 0x200 );
			}
		}

		u8 ecc[0x10];
		memset( ecc, 0xFF, 0x10 );

		for ( int i = 0; i < 4; ++i ) {
			FolderMemoryCard::CalculateECC( ecc + ( i * 3 ), &data[i * 0x80] );
		}
		
		memcpy( dest + eccOffset, ecc, eccLength );
	}

	// return 0 on fail, 1 on success?
	return 1;
}

s32 FolderMemoryCard::Save(const u8 *src, u32 adr, int size)
{
	const u32 block = adr / 0x2100u;
	const u32 cluster = adr / 0x420u;
	const u32 page = adr / 0x210u;
	const u32 offset = adr % 0x210u;
	const u32 end = offset + size;
	Console.WriteLn( L"(FolderMcd) writing %03d bytes at %08x / block %04x, cluster %05x, page %05x, offset %03x", size, adr, block, cluster, page, offset );

	if ( end > 0x210 ) {
		// is trying to store more than one page at a time
		// do this recursively so that each function call only has to care about one page
		const u32 toNextPage = 0x210u - offset;
		Save( src + toNextPage, adr + toNextPage, size - toNextPage );
		size = toNextPage;
	}

	if ( offset < 0x200 ) {
		// is trying to store (part of) an actual data block
		const u32 dataLength = std::min( (u32)size, 0x200u - offset );

		if ( duringFormatting ) {
			// fake all access because it's only doing "is this block writable? erasable?" stuff
			if ( adr == 0x2100 && src[0] != 0x00 && src[0] != 0xFF ) {
				// writing indirect FAT cluster
				// from now on, we can use regular addressing instead of the weird faking we did before
				formatted = true;
				duringFormatting = false;
			} else {
				m_fakeFormattingData = src[0];
				return 1;
			}
		}

		u8* dest = GetSystemBlockPointer( adr );
		if ( dest != nullptr ) {
			memcpy( dest, src, dataLength );
			Console.WriteLn( L"(FolderMcd) %02x %02x %02x %02x  %02x %02x %02x %02x", src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7] );
			if ( adr == 0 && size == 0x80 ) {
				// check for arbitrary byte in the superblock that needs to be set for it to be valid
				if ( src[0x16] != 0x6F ) {
					// presumably part of the formatting procedure
					// the order formatting writes data doesn't work with this implementation,
					// so work around this by manually fake-formatting the superblock to sensible defaults
					// and faking read/writes to the superblock until it actually writes it
					formatted = true;
					duringFormatting = true;
					superBlock.data.backup_block1 = 0x03FF;
					superBlock.data.backup_block2 = 0x03FE;
					superBlock.data.ifc_list[0] = 0x0008;
					superBlock.data.alloc_offset = 0x29;
					superBlock.data.alloc_end = 0x1FC7;
					m_fakeFormattingData = src[0];
				}
			}
		} else {
			WriteToFile( src, adr, dataLength );
		}
	}

	if ( end > 0x200 ) {
		// is trying to store ECC
		// simply ignore this, is automatically generated when reading
	}

	// return 0 on fail, 1 on success?
	return 1;
}

bool FolderMemoryCard::WriteToFile( const u8* src, u32 adr, u32 dataLength ) {
	const u32 cluster = adr / 0x420u;
	const u32 page = adr / 0x210u;
	const u32 offset = adr % 0x210u;
	const u32 fatCluster = cluster - superBlock.data.alloc_offset;

	// figure out which file to write to
	wxFileName fileName( folderName );
	u32 clusterNumber;
	const MemoryCardFileEntry* const entry = GetFileEntryFromFileDataCluster( superBlock.data.rootdir_cluster, fatCluster, &fileName, fileName.GetDirCount(), &clusterNumber );
	if ( entry != nullptr ) {
		Console.WriteLn( L"(FolderMcd) Writing to file: %s", fileName.GetFullPath().c_str() );
		if ( !fileName.DirExists() ) {
			fileName.Mkdir();
		}
		wxFFile file( fileName.GetFullPath(), L"r+b" );
		if ( file.IsOpened() ) {
			const u32 clusterOffset = ( page % 2 ) * 0x200u + offset;
			const u32 fileSize = entry->entry.data.length;
			const u32 fileOffsetStart = std::min( clusterNumber * 0x400u + clusterOffset, fileSize );;
			const u32 fileOffsetEnd = std::min( fileOffsetStart + dataLength, fileSize );
			const u32 bytesToWrite = fileOffsetEnd - fileOffsetStart;
			Console.WriteLn( L"(FolderMcd) Writing %03d bytes at %08x, corresponds to cluster %d offset %03x or file offset %06x", bytesToWrite, adr, clusterNumber, clusterOffset, fileOffsetStart );

			file.Seek( fileOffsetStart );
			if ( bytesToWrite > 0 ) {
				file.Write( src, bytesToWrite );
			}

			file.Close();

			return true;
		}
	} else {
		Console.WriteLn( L"(FolderMcd) Writing to nothing???" );
	}

	return false;
}

s32 FolderMemoryCard::EraseBlock(u32 adr)
{
	const u32 block = adr / 0x2100u;
	Console.WriteLn( L"(FolderMcd) erasing block at %08x / block %04x", adr, block );

	if ( duringFormatting ) {
		// fake all access
		m_fakeFormattingData = 0xFF;
		return 1;
	}

	for ( int page = 0; page < 16; ++page ) {
		u8* const dest = GetSystemBlockPointer( block * 0x2100 + page * 0x210 );
		if ( dest != nullptr ) {
			memset( dest, 0xFF, 0x200 );
		} else {
			// TODO: delete files I guess?
		}
	}

	// return 0 on fail, 1 on success?
	return 1;
}

u64 FolderMemoryCard::GetCRC()
{
	// TODO: Implement
	u64 retval = 0;
	return retval;
}

void FolderMemoryCard::SetSlot(uint slot)
{
	pxAssert( slot < 8 );
	this->slot = slot;
}

// from http://www.oocities.org/siliconvalley/station/8269/sma02/sma02.html#ECC
void FolderMemoryCard::CalculateECC( u8* ecc, const u8* data ) {
	static const u8 Table[] = {
		0x00, 0x87, 0x96, 0x11, 0xa5, 0x22, 0x33, 0xb4, 0xb4, 0x33, 0x22, 0xa5, 0x11, 0x96, 0x87, 0x00,
		0xc3, 0x44, 0x55, 0xd2, 0x66, 0xe1, 0xf0, 0x77, 0x77, 0xf0, 0xe1, 0x66, 0xd2, 0x55, 0x44, 0xc3,
		0xd2, 0x55, 0x44, 0xc3, 0x77, 0xf0, 0xe1, 0x66, 0x66, 0xe1, 0xf0, 0x77, 0xc3, 0x44, 0x55, 0xd2,
		0x11, 0x96, 0x87, 0x00, 0xb4, 0x33, 0x22, 0xa5, 0xa5, 0x22, 0x33, 0xb4, 0x00, 0x87, 0x96, 0x11,
		0xe1, 0x66, 0x77, 0xf0, 0x44, 0xc3, 0xd2, 0x55, 0x55, 0xd2, 0xc3, 0x44, 0xf0, 0x77, 0x66, 0xe1,
		0x22, 0xa5, 0xb4, 0x33, 0x87, 0x00, 0x11, 0x96, 0x96, 0x11, 0x00, 0x87, 0x33, 0xb4, 0xa5, 0x22,
		0x33, 0xb4, 0xa5, 0x22, 0x96, 0x11, 0x00, 0x87, 0x87, 0x00, 0x11, 0x96, 0x22, 0xa5, 0xb4, 0x33,
		0xf0, 0x77, 0x66, 0xe1, 0x55, 0xd2, 0xc3, 0x44, 0x44, 0xc3, 0xd2, 0x55, 0xe1, 0x66, 0x77, 0xf0,
		0xf0, 0x77, 0x66, 0xe1, 0x55, 0xd2, 0xc3, 0x44, 0x44, 0xc3, 0xd2, 0x55, 0xe1, 0x66, 0x77, 0xf0,
		0x33, 0xb4, 0xa5, 0x22, 0x96, 0x11, 0x00, 0x87, 0x87, 0x00, 0x11, 0x96, 0x22, 0xa5, 0xb4, 0x33,
		0x22, 0xa5, 0xb4, 0x33, 0x87, 0x00, 0x11, 0x96, 0x96, 0x11, 0x00, 0x87, 0x33, 0xb4, 0xa5, 0x22,
		0xe1, 0x66, 0x77, 0xf0, 0x44, 0xc3, 0xd2, 0x55, 0x55, 0xd2, 0xc3, 0x44, 0xf0, 0x77, 0x66, 0xe1,
		0x11, 0x96, 0x87, 0x00, 0xb4, 0x33, 0x22, 0xa5, 0xa5, 0x22, 0x33, 0xb4, 0x00, 0x87, 0x96, 0x11,
		0xd2, 0x55, 0x44, 0xc3, 0x77, 0xf0, 0xe1, 0x66, 0x66, 0xe1, 0xf0, 0x77, 0xc3, 0x44, 0x55, 0xd2,
		0xc3, 0x44, 0x55, 0xd2, 0x66, 0xe1, 0xf0, 0x77, 0x77, 0xf0, 0xe1, 0x66, 0xd2, 0x55, 0x44, 0xc3,
		0x00, 0x87, 0x96, 0x11, 0xa5, 0x22, 0x33, 0xb4, 0xb4, 0x33, 0x22, 0xa5, 0x11, 0x96, 0x87, 0x00
	};

	int i, c;

	ecc[0] = ecc[1] = ecc[2] = 0;

	for ( i = 0; i < 0x80; i++ ) {
		c = Table[data[i]];

		ecc[0] ^= c;
		if ( c & 0x80 ) {
			ecc[1] ^= ~i;
			ecc[2] ^= i;
		}
	}
	ecc[0] = ~ecc[0];
	ecc[0] &= 0x77;

	ecc[1] = ~ecc[1];
	ecc[1] &= 0x7f;

	ecc[2] = ~ecc[2];
	ecc[2] &= 0x7f;

	return;
}

// --------------------------------------------------------------------------------------
//  FolderMemoryCardAggregator
// --------------------------------------------------------------------------------------
// Forwards the API's requests for specific memory card slots to the correct FolderMemoryCard.
class FolderMemoryCardAggregator
{
protected:
	static const int totalCardSlots = 8;
	FolderMemoryCard m_cards[totalCardSlots];

public:
	FolderMemoryCardAggregator();
	virtual ~FolderMemoryCardAggregator() throw() {}

	void Open();
	void Close();

	s32  IsPresent(uint slot);
	void GetSizeInfo(uint slot, PS2E_McdSizeInfo& outways);
	bool IsPSX(uint slot);
	s32  Read(uint slot, u8 *dest, u32 adr, int size);
	s32  Save(uint slot, const u8 *src, u32 adr, int size);
	s32  EraseBlock(uint slot, u32 adr);
	u64  GetCRC(uint slot);
};

FolderMemoryCardAggregator::FolderMemoryCardAggregator()
{
	for ( uint i = 0; i < totalCardSlots; ++i ) {
		m_cards[i].SetSlot( i );
	}
}

void FolderMemoryCardAggregator::Open()
{
	for (int i = 0; i < totalCardSlots; ++i) {
		m_cards[i].Open();
	}
}

void FolderMemoryCardAggregator::Close()
{
	for (int i = 0; i < totalCardSlots; ++i) {
		m_cards[i].Close();
	}
}

s32 FolderMemoryCardAggregator::IsPresent(uint slot)
{
	return m_cards[slot].IsPresent();
}

void FolderMemoryCardAggregator::GetSizeInfo(uint slot, PS2E_McdSizeInfo& outways)
{
	m_cards[slot].GetSizeInfo(outways);
}

bool FolderMemoryCardAggregator::IsPSX(uint slot)
{
	return m_cards[slot].IsPSX();
}

s32 FolderMemoryCardAggregator::Read(uint slot, u8 *dest, u32 adr, int size)
{
	return m_cards[slot].Read(dest, adr, size);
}

s32 FolderMemoryCardAggregator::Save(uint slot, const u8 *src, u32 adr, int size)
{
	return m_cards[slot].Save(src, adr, size);
}

s32 FolderMemoryCardAggregator::EraseBlock(uint slot, u32 adr)
{
	return m_cards[slot].EraseBlock(adr);
}

u64 FolderMemoryCardAggregator::GetCRC(uint slot)
{
	return m_cards[slot].GetCRC();
}

// --------------------------------------------------------------------------------------
//  MemoryCard Component API Bindings
// --------------------------------------------------------------------------------------

struct Component_FileMcd
{
	PS2E_ComponentAPI_Mcd	api;	// callbacks the plugin provides back to the emulator
	//FileMemoryCard			impl;	// class-based implementations we refer to when API is invoked
	FolderMemoryCardAggregator impl;

	Component_FileMcd();
};

uint FileMcd_ConvertToSlot( uint port, uint slot )
{
	if( slot == 0 ) return port;
	if( port == 0 ) return slot+1;		// multitap 1
	return slot + 4;					// multitap 2
}

static void PS2E_CALLBACK FileMcd_EmuOpen( PS2E_THISPTR thisptr, const PS2E_SessionInfo *session )
{
	thisptr->impl.Open();
}

static void PS2E_CALLBACK FileMcd_EmuClose( PS2E_THISPTR thisptr )
{
	thisptr->impl.Close();
}

static s32 PS2E_CALLBACK FileMcd_IsPresent( PS2E_THISPTR thisptr, uint port, uint slot )
{
	return thisptr->impl.IsPresent( FileMcd_ConvertToSlot( port, slot ) );
}

static void PS2E_CALLBACK FileMcd_GetSizeInfo( PS2E_THISPTR thisptr, uint port, uint slot, PS2E_McdSizeInfo* outways )
{
	thisptr->impl.GetSizeInfo( FileMcd_ConvertToSlot( port, slot ), *outways );
}

static bool PS2E_CALLBACK FileMcd_IsPSX( PS2E_THISPTR thisptr, uint port, uint slot )
{
	return thisptr->impl.IsPSX( FileMcd_ConvertToSlot( port, slot ) );
}

static s32 PS2E_CALLBACK FileMcd_Read( PS2E_THISPTR thisptr, uint port, uint slot, u8 *dest, u32 adr, int size )
{
	return thisptr->impl.Read( FileMcd_ConvertToSlot( port, slot ), dest, adr, size );
}

static s32 PS2E_CALLBACK FileMcd_Save( PS2E_THISPTR thisptr, uint port, uint slot, const u8 *src, u32 adr, int size )
{
	return thisptr->impl.Save( FileMcd_ConvertToSlot( port, slot ), src, adr, size );
}

static s32 PS2E_CALLBACK FileMcd_EraseBlock( PS2E_THISPTR thisptr, uint port, uint slot, u32 adr )
{
	return thisptr->impl.EraseBlock( FileMcd_ConvertToSlot( port, slot ), adr );
}

static u64 PS2E_CALLBACK FileMcd_GetCRC( PS2E_THISPTR thisptr, uint port, uint slot )
{
	return thisptr->impl.GetCRC( FileMcd_ConvertToSlot( port, slot ) );
}

Component_FileMcd::Component_FileMcd()
{
	memzero( api );

	api.Base.EmuOpen	= FileMcd_EmuOpen;
	api.Base.EmuClose	= FileMcd_EmuClose;

	api.McdIsPresent	= FileMcd_IsPresent;
	api.McdGetSizeInfo	= FileMcd_GetSizeInfo;
	api.McdIsPSX		= FileMcd_IsPSX;
	api.McdRead			= FileMcd_Read;
	api.McdSave			= FileMcd_Save;
	api.McdEraseBlock	= FileMcd_EraseBlock;
	api.McdGetCRC		= FileMcd_GetCRC;
}


// --------------------------------------------------------------------------------------
//  Library API Implementations
// --------------------------------------------------------------------------------------
static const char* PS2E_CALLBACK FileMcd_GetName()
{
	return "PlainJane Mcd";
}

static const PS2E_VersionInfo* PS2E_CALLBACK FileMcd_GetVersion( u32 component )
{
	static const PS2E_VersionInfo version = { 0,1,0, SVN_REV };
	return &version;
}

static s32 PS2E_CALLBACK FileMcd_Test( u32 component, const PS2E_EmulatorInfo* xinfo )
{
	if( component != PS2E_TYPE_Mcd ) return 0;

	// Check and make sure the user has a hard drive?
	// Probably not necessary :p
	return 1;
}

static PS2E_THISPTR PS2E_CALLBACK FileMcd_NewComponentInstance( u32 component )
{
	if( component != PS2E_TYPE_Mcd ) return NULL;

	try
	{
		return new Component_FileMcd();
	}
	catch( std::bad_alloc& )
	{
		Console.Error( "Allocation failed on Component_FileMcd! (out of memory?)" );
	}
	return NULL;
}

static void PS2E_CALLBACK FileMcd_DeleteComponentInstance( PS2E_THISPTR instance )
{
	delete instance;
}

static void PS2E_CALLBACK FileMcd_SetSettingsFolder( const char* folder )
{
}

static void PS2E_CALLBACK FileMcd_SetLogFolder( const char* folder )
{
}

static const PS2E_LibraryAPI FileMcd_Library =
{
	FileMcd_GetName,
	FileMcd_GetVersion,
	FileMcd_Test,
	FileMcd_NewComponentInstance,
	FileMcd_DeleteComponentInstance,
	FileMcd_SetSettingsFolder,
	FileMcd_SetLogFolder
};

// If made into an external plugin, this function should be renamed to PS2E_InitAPI, so that
// PCSX2 can find the export in the expected location.
extern "C" const PS2E_LibraryAPI* FileMcd_InitAPI( const PS2E_EmulatorInfo* emuinfo )
{
	return &FileMcd_Library;
}

//Tests if a string is a valid name for a new file within a specified directory.
//returns true if:
//     - the file name has a minimum length of minNumCharacters chars (default is 5 chars: at least 1 char + '.' + 3-chars extension)
// and - the file name is within the basepath directory (doesn't contain .. , / , \ , etc)
// and - file name doesn't already exist
// and - can be created on current system (it is actually created and deleted for this test).
bool isValidNewFilename( wxString filenameStringToTest, wxDirName atBasePath, wxString& out_errorMessage, uint minNumCharacters)
{
	if ( filenameStringToTest.Length()<1 || filenameStringToTest.Length()<minNumCharacters )
	{
		out_errorMessage = _("File name empty or too short");
		return false;
	}

	if( (atBasePath + wxFileName(filenameStringToTest)).GetFullPath() != (atBasePath + wxFileName(filenameStringToTest).GetFullName()).GetFullPath() ){
		out_errorMessage = _("File name outside of required directory");
		return false;
	}

	if ( wxFileExists( (atBasePath + wxFileName(filenameStringToTest)).GetFullPath() ))
	{
		out_errorMessage = _("File name already exists");
		return false;
	}

	wxFile fp;
	if( !fp.Create( (atBasePath + wxFileName(filenameStringToTest)).GetFullPath() ))
	{
		out_errorMessage = _("The Operating-System prevents this file from being created");
		return false;
	}
	fp.Close();
	wxRemoveFile( (atBasePath + wxFileName(filenameStringToTest)).GetFullPath() );

	out_errorMessage = L"[OK - New file name is valid]";  //shouldn't be displayed on success, hence not translatable.
	return true;
}
