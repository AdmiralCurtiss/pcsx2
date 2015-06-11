/*  PCSX2 - PS2 Emulator for PCs
 *  Copyright (C) 2002-2015  PCSX2 Dev Team
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

#include "MemoryCardFile.h"
#include "MemoryCardFolder.h"

#include "System.h"
#include "AppConfig.h"

#include "svnrev.h"

FolderMemoryCard::FolderMemoryCard() {
	m_slot = 0;
	m_isEnabled = false;
}

void FolderMemoryCard::InitializeInternalData() {
	memset( &m_superBlock, 0xFF, sizeof( m_superBlock ) );
	memset( &m_indirectFat, 0xFF, sizeof( m_indirectFat ) );
	memset( &m_fat, 0xFF, sizeof( m_fat ) );
	memset( &m_backupBlock1, 0xFF, sizeof( m_backupBlock1 ) );
	memset( &m_backupBlock2, 0xFF, sizeof( m_backupBlock2 ) );
	m_cache.clear();
	m_fileMetadataQuickAccess.clear();
	m_timeLastWritten = 0;
	m_isEnabled = false;
	m_framesUntilFlush = 0;
	m_lastAccessedFile.Close();
}

bool FolderMemoryCard::IsFormatted() {
	// this should be a good enough arbitrary check, if someone can think of a case where this doesn't work feel free to change
	return m_superBlock.raw[0x16] == 0x6F;
}

void FolderMemoryCard::Open( const bool enableFiltering, const wxString& filter ) {
	Open( g_Conf->FullpathToMcd( m_slot ), g_Conf->Mcd[m_slot], enableFiltering, filter );
}

void FolderMemoryCard::Open( const wxString& fullPath, const AppConfig::McdOptions& mcdOptions, const bool enableFiltering, const wxString& filter ) {
	InitializeInternalData();

	wxFileName configuredFileName( fullPath );
	m_folderName = wxFileName( configuredFileName.GetFullPath() + L"/" );
	wxString str( configuredFileName.GetFullPath() );
	bool disabled = false;

	if ( mcdOptions.Enabled && mcdOptions.Type == MemoryCardType::MemoryCard_Folder ) {
		if ( configuredFileName.GetFullName().IsEmpty() ) {
			str = L"[empty filename]";
			disabled = true;
		}
		if ( !disabled && configuredFileName.FileExists() ) {
			str = L"[is file, should be folder]";
			disabled = true;
		}

		// if nothing exists at a valid location, create a directory for the memory card
		if ( !disabled && !m_folderName.DirExists() ) {
			if ( !m_folderName.Mkdir() ) {
				str = L"[couldn't create folder]";
				disabled = true;
			}
		}
	} else {
		str = L"[disabled]";
		disabled = true;
	}

	Console.WriteLn( disabled ? Color_Gray : Color_Green, L"McdSlot %u: [Folder] " + str, m_slot );
	if ( disabled ) return;

	m_isEnabled = true;
	LoadMemoryCardData( enableFiltering, filter );

	SetTimeLastWrittenToNow();
	m_framesUntilFlush = 0;
}

void FolderMemoryCard::Close() {
	if ( !m_isEnabled ) { return; }

	Flush();

	wxFileName superBlockFileName( m_folderName.GetPath(), L"_pcsx2_superblock" );
	wxFFile superBlockFile( superBlockFileName.GetFullPath().c_str(), L"wb" );
	if ( superBlockFile.IsOpened() ) {
		superBlockFile.Write( &m_superBlock.raw, sizeof( m_superBlock.raw ) );
	}

	m_cache.clear();
	m_fileMetadataQuickAccess.clear();
	m_lastAccessedFile.Close();
}

void FolderMemoryCard::LoadMemoryCardData( const bool enableFiltering, const wxString& filter ) {
	bool formatted = false;

	// read superblock if it exists
	wxFileName superBlockFileName( m_folderName.GetPath(), L"_pcsx2_superblock" );
	if ( superBlockFileName.FileExists() ) {
		wxFFile superBlockFile( superBlockFileName.GetFullPath().c_str(), L"rb" );
		if ( superBlockFile.IsOpened() && superBlockFile.Read( &m_superBlock.raw, sizeof( m_superBlock.raw ) ) >= sizeof( m_superBlock.data ) ) {
			formatted = IsFormatted();
		}
	}

	// if superblock was valid, load folders and files
	if ( formatted ) {
		if ( enableFiltering ) {
			Console.WriteLn( Color_Green, L"(FolderMcd) Indexing slot %u with filter \"%s\".", m_slot, WX_STR( filter ) );
		} else {
			Console.WriteLn( Color_Green, L"(FolderMcd) Indexing slot %u without filter.", m_slot );
		}

		CreateFat();
		CreateRootDir();
		MemoryCardFileEntry* const rootDirEntry = &m_fileEntryDict[m_superBlock.data.rootdir_cluster].entries[0];
		AddFolder( rootDirEntry, m_folderName.GetPath(), nullptr, enableFiltering, filter );
	}
}

void FolderMemoryCard::CreateFat() {
	const u32 totalClusters = m_superBlock.data.clusters_per_card;
	const u32 clusterSize = m_superBlock.data.page_len * m_superBlock.data.pages_per_cluster;
	const u32 fatEntriesPerCluster = clusterSize / 4;
	const u32 countFatClusters = ( totalClusters % fatEntriesPerCluster ) != 0 ? ( totalClusters / fatEntriesPerCluster + 1 ) : ( totalClusters / fatEntriesPerCluster );
	const u32 countDataClusters = m_superBlock.data.alloc_end;

	// create indirect FAT
	for ( unsigned int i = 0; i < countFatClusters; ++i ) {
		m_indirectFat.data[0][i] = GetFreeSystemCluster();
	}

	// fill FAT with default values
	for ( unsigned int i = 0; i < countDataClusters; ++i ) {
		m_fat.data[0][0][i].data.cluster = MemoryCardFatClusterNumber::LastClusterOfData;
		m_fat.data[0][0][i].data.used = 0;
	}
}

void FolderMemoryCard::CreateRootDir() {
	MemoryCardFileEntryCluster* const rootCluster = &m_fileEntryDict[m_superBlock.data.rootdir_cluster];
	memset( &rootCluster->entries[0].entry.raw[0], 0x00, 0x200 );
	rootCluster->entries[0].entry.data.mode = 0x8427;
	rootCluster->entries[0].entry.data.length = 2;
	rootCluster->entries[0].entry.data.name[0] = '.';

	memset( &rootCluster->entries[1].entry.raw[0], 0x00, 0x200 );
	rootCluster->entries[1].entry.data.mode = 0xA426;
	rootCluster->entries[1].entry.data.name[0] = '.';
	rootCluster->entries[1].entry.data.name[1] = '.';

	// mark root dir cluster as used
	m_fat.data[0][0][m_superBlock.data.rootdir_cluster].data.cluster = MemoryCardFatClusterNumber::LastClusterOfData;
	m_fat.data[0][0][m_superBlock.data.rootdir_cluster].data.used = 1;
}

u32 FolderMemoryCard::GetFreeSystemCluster() {
	// first block is reserved for superblock
	u32 highestUsedCluster = ( m_superBlock.data.pages_per_block / m_superBlock.data.pages_per_cluster ) - 1;

	// can't use any of the indirect fat clusters
	for ( int i = 0; i < IndirectFatClusterCount; ++i ) {
		highestUsedCluster = std::max( highestUsedCluster, m_superBlock.data.ifc_list[i] );
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
	// BIOS reports different cluster values than what the memory card actually has, match that when adding files
	//  8mb card -> BIOS:  7999 clusters / Superblock:  8135 clusters
	// 16mb card -> BIOS: 15999 clusters / Superblock: 16295 clusters
	// 32mb card -> BIOS: 31999 clusters / Superblock: 32615 clusters
	// 64mb card -> BIOS: 64999 clusters / Superblock: 65255 clusters
	const u32 countDataClusters = ( m_superBlock.data.alloc_end / 1000 ) * 1000 - 1;

	for ( unsigned int i = 0; i < countDataClusters; ++i ) {
		const MemoryCardFatClusterNumber cluster = m_fat.data[0][0][i];

		if ( cluster.data.used == 0 ) {
			return i;
		}
	}

	return 0xFFFFFFFF;
}

u32 FolderMemoryCard::GetAmountFreeDataClusters() {
	const u32 countDataClusters = ( m_superBlock.data.alloc_end / 1000 ) * 1000 - 1;
	u32 countFreeDataClusters = 0;

	for ( unsigned int i = 0; i < countDataClusters; ++i ) {
		const MemoryCardFatClusterNumber cluster = m_fat.data[0][0][i];

		if ( cluster.data.used == 0 ) {
			++countFreeDataClusters;
		}
	}

	return countFreeDataClusters;
}

u32 FolderMemoryCard::GetLastClusterOfData( const u32 cluster ) {
	u32 entryCluster;
	u32 nextCluster = cluster;
	do {
		entryCluster = nextCluster;
		nextCluster = m_fat.data[0][0][entryCluster].data.cluster;
	} while ( nextCluster != MemoryCardFatClusterNumber::LastClusterOfData );
	return entryCluster;
}

MemoryCardFileEntry* FolderMemoryCard::AppendFileEntryToDir( MemoryCardFileEntry* const dirEntry ) {
	u32 entryCluster = GetLastClusterOfData( dirEntry->entry.data.cluster );

	MemoryCardFileEntry* newFileEntry;
	if ( dirEntry->entry.data.length % 2 == 0 ) {
		// need new cluster
		u32 newCluster = GetFreeDataCluster();
		if ( newCluster == 0xFFFFFFFFu ) { return nullptr; }
		m_fat.data[0][0][entryCluster].data.cluster = newCluster;
		m_fat.data[0][0][entryCluster].data.used = 1;
		m_fat.data[0][0][newCluster].data.cluster = MemoryCardFatClusterNumber::LastClusterOfData;
		m_fat.data[0][0][newCluster].data.used = 1;
		newFileEntry = &m_fileEntryDict[newCluster].entries[0];
	} else {
		// can use last page of existing clusters
		newFileEntry = &m_fileEntryDict[entryCluster].entries[1];
	}

	return newFileEntry;
}

bool FilterMatches( const wxString& fileName, const wxString& filter ) {
	size_t start = 0;
	size_t len = filter.Len();
	while ( start < len ) {
		size_t end = filter.find( '/', start );
		if ( end == wxString::npos ) {
			end = len;
		}

		wxString singleFilter = filter.Mid( start, end - start );
		if ( fileName.Contains( singleFilter ) ) {
			return true;
		}

		start = end + 1;
	}

	return false;
}

bool FolderMemoryCard::AddFolder( MemoryCardFileEntry* const dirEntry, const wxString& dirPath, MemoryCardFileMetadataReference* parent, const bool enableFiltering, const wxString& filter ) {
	wxDir dir( dirPath );
	if ( dir.IsOpened() ) {
		Console.WriteLn( L"(FolderMcd) Adding folder: %s", WX_STR( dirPath ) );

		const u32 dirStartCluster = dirEntry->entry.data.cluster;

		wxString fileName;
		bool hasNext;

		wxString localFilter;
		if ( enableFiltering ) {
			bool hasFilter = !filter.IsEmpty();
			if ( hasFilter ) {
				localFilter = L"DATA-SYSTEM/" + filter;
			} else {
				localFilter = L"DATA-SYSTEM";
			}
		}

		int entryNumber = 2; // include . and ..
		hasNext = dir.GetFirst( &fileName );
		while ( hasNext ) {
			if ( fileName.StartsWith( L"_pcsx2_" ) ) {
				hasNext = dir.GetNext( &fileName );
				continue;
			}

			wxFileName fileInfo( dirPath, fileName );
			bool isFile = wxFile::Exists( fileInfo.GetFullPath() );

			if ( isFile ) {
				if ( AddFile( dirEntry, dirPath, fileName, parent ) ) {
					++entryNumber;
				}
			} else {
				// if possible filter added directories by game serial
				// this has the effective result of only files relevant to the current game being loaded into the memory card
				// which means every game essentially sees the memory card as if no other files exist
				if ( enableFiltering && !FilterMatches( fileName, localFilter ) ) {
					hasNext = dir.GetNext( &fileName );
					continue;
				}

				// make sure we have enough space on the memcard for the directory
				const u32 newNeededClusters = ( dirEntry->entry.data.length % 2 ) == 0 ? 2 : 1;
				if ( newNeededClusters > GetAmountFreeDataClusters() ) {
					Console.Warning( GetCardFullMessage( fileName ) );
					hasNext = dir.GetNext( &fileName );
					continue;
				}

				// is a subdirectory
				wxDateTime creationTime, modificationTime;
				fileInfo.AppendDir( fileInfo.GetFullName() );
				fileInfo.SetName( L"" );
				fileInfo.ClearExt();
				fileInfo.GetTimes( NULL, &modificationTime, &creationTime );

				// add entry for subdir in parent dir
				MemoryCardFileEntry* newDirEntry = AppendFileEntryToDir( dirEntry );
				dirEntry->entry.data.length++;

				// set metadata
				wxFileName metaFileName( dirPath, L"_pcsx2_meta_directory" );
				metaFileName.AppendDir( fileName );
				wxFFile metaFile;
				if ( metaFileName.FileExists() && metaFile.Open( metaFileName.GetFullPath(), L"rb" ) ) {
					metaFile.Read( &newDirEntry->entry.raw, 0x40 );
					metaFile.Close();
				} else {
					newDirEntry->entry.data.mode = MemoryCardFileEntry::DefaultDirMode;
					newDirEntry->entry.data.timeCreated = MemoryCardFileEntryDateTime::FromWxDateTime( creationTime );
					newDirEntry->entry.data.timeModified = MemoryCardFileEntryDateTime::FromWxDateTime( modificationTime );
				}

				newDirEntry->entry.data.length = 2;
				strcpy( (char*)&newDirEntry->entry.data.name[0], fileName.mbc_str() );

				// create new cluster for . and .. entries
				u32 newCluster = GetFreeDataCluster();
				m_fat.data[0][0][newCluster].data.cluster = MemoryCardFatClusterNumber::LastClusterOfData;
				m_fat.data[0][0][newCluster].data.used = 1;
				newDirEntry->entry.data.cluster = newCluster;

				MemoryCardFileEntryCluster* const subDirCluster = &m_fileEntryDict[newCluster];
				memset( &subDirCluster->entries[0].entry.raw[0], 0x00, 0x200 );
				subDirCluster->entries[0].entry.data.mode = MemoryCardFileEntry::DefaultDirMode;
				subDirCluster->entries[0].entry.data.dirEntry = entryNumber;
				subDirCluster->entries[0].entry.data.name[0] = '.';

				memset( &subDirCluster->entries[1].entry.raw[0], 0x00, 0x200 );
				subDirCluster->entries[1].entry.data.mode = MemoryCardFileEntry::DefaultDirMode;
				subDirCluster->entries[1].entry.data.name[0] = '.';
				subDirCluster->entries[1].entry.data.name[1] = '.';

				MemoryCardFileMetadataReference* dirRef = AddDirEntryToMetadataQuickAccess( newDirEntry, parent );

				++entryNumber;

				// and add all files in subdir
				AddFolder( newDirEntry, fileInfo.GetFullPath(), dirRef );
			}

			hasNext = dir.GetNext( &fileName );
		}

		return true;
	}

	return false;
}

bool FolderMemoryCard::AddFile( MemoryCardFileEntry* const dirEntry, const wxString& dirPath, const wxString& fileName, MemoryCardFileMetadataReference* parent ) {
	wxFileName relativeFilePath( dirPath, fileName );
	relativeFilePath.MakeRelativeTo( m_folderName.GetPath() );
	Console.WriteLn( L"(FolderMcd) Adding file: %s", WX_STR( relativeFilePath.GetFullPath() ) );

	wxFileName fileInfo( dirPath, fileName );
	wxFFile file( fileInfo.GetFullPath(), L"rb" );
	if ( file.IsOpened() ) {
		// make sure we have enough space on the memcard to hold the data
		const u32 clusterSize = m_superBlock.data.pages_per_cluster * m_superBlock.data.page_len;
		const u32 filesize = file.Length();
		const u32 countClusters = ( filesize % clusterSize ) != 0 ? ( filesize / clusterSize + 1 ) : ( filesize / clusterSize );
		const u32 newNeededClusters = ( dirEntry->entry.data.length % 2 ) == 0 ? countClusters + 1 : countClusters;
		if ( newNeededClusters > GetAmountFreeDataClusters() ) {
			Console.Warning( GetCardFullMessage( relativeFilePath.GetFullPath() ) );
			file.Close();
			return false;
		}

		MemoryCardFileEntry* newFileEntry = AppendFileEntryToDir( dirEntry );
		wxDateTime creationTime, modificationTime;
		fileInfo.GetTimes( NULL, &modificationTime, &creationTime );

		// set file entry metadata
		memset( &newFileEntry->entry.raw[0], 0x00, 0x200 );

		wxFileName metaFileName( dirPath, fileName );
		metaFileName.AppendDir( L"_pcsx2_meta" );
		wxFFile metaFile;
		if ( metaFileName.FileExists() && metaFile.Open( metaFileName.GetFullPath(), L"rb" ) ) {
			metaFile.Read( &newFileEntry->entry.raw, 0x40 );
			metaFile.Close();
		} else {
			newFileEntry->entry.data.mode = MemoryCardFileEntry::DefaultFileMode;
			newFileEntry->entry.data.timeCreated = MemoryCardFileEntryDateTime::FromWxDateTime( creationTime );
			newFileEntry->entry.data.timeModified = MemoryCardFileEntryDateTime::FromWxDateTime( modificationTime );
		}

		newFileEntry->entry.data.length = filesize;
		u32 fileDataStartingCluster = GetFreeDataCluster();
		newFileEntry->entry.data.cluster = fileDataStartingCluster;
		strcpy( (char*)&newFileEntry->entry.data.name[0], fileName.mbc_str() );

		// mark the appropriate amount of clusters as used
		u32 dataCluster = fileDataStartingCluster;
		m_fat.data[0][0][dataCluster].data.cluster = MemoryCardFatClusterNumber::LastClusterOfData;
		m_fat.data[0][0][dataCluster].data.used = 1;
		for ( unsigned int i = 0; i < countClusters - 1; ++i ) {
			u32 newCluster = GetFreeDataCluster();
			m_fat.data[0][0][dataCluster].data.cluster = newCluster;
			m_fat.data[0][0][dataCluster].data.used = 1;
			m_fat.data[0][0][newCluster].data.cluster = MemoryCardFatClusterNumber::LastClusterOfData;
			m_fat.data[0][0][newCluster].data.used = 1;
			dataCluster = newCluster;
		}

		file.Close();

		AddFileEntryToMetadataQuickAccess( newFileEntry, parent );
	} else {
		Console.WriteLn( L"(FolderMcd) Could not open file: %s", WX_STR( relativeFilePath.GetFullPath() ) );
		return false;
	}

	// and finally, increase file count in the directory entry
	dirEntry->entry.data.length++;

	return true;
}

MemoryCardFileMetadataReference* FolderMemoryCard::AddDirEntryToMetadataQuickAccess( MemoryCardFileEntry* const entry, MemoryCardFileMetadataReference* const parent ) {
	MemoryCardFileMetadataReference* ref = &m_fileMetadataQuickAccess[entry->entry.data.cluster];
	ref->parent = parent;
	ref->entry = entry;
	ref->consecutiveCluster = 0xFFFFFFFFu;
	return ref;
}

void FolderMemoryCard::AddFileEntryToMetadataQuickAccess( MemoryCardFileEntry* const entry, MemoryCardFileMetadataReference* const parent ) {
	u32 fileCluster = entry->entry.data.cluster;

	// zero-length files have no file clusters
	if ( fileCluster == 0xFFFFFFFFu ) {
		return;
	}

	u32 clusterNumber = 0;
	do {
		MemoryCardFileMetadataReference* ref = &m_fileMetadataQuickAccess[fileCluster & 0x7FFFFFFFu];
		ref->parent = parent;
		ref->entry = entry;
		ref->consecutiveCluster = clusterNumber;
		++clusterNumber;
	} while ( ( fileCluster = m_fat.data[0][0][fileCluster].raw ) != 0xFFFFFFFFu );
}

void MemoryCardFileMetadataReference::GetPath( wxFileName* fileName ) {
	if ( parent ) {
		parent->GetPath( fileName );
	}

	if ( entry->IsDir() ) {
		fileName->AppendDir( wxString::FromAscii( (const char*)entry->entry.data.name ) );
	} else if ( entry->IsFile() ) {
		fileName->SetName( wxString::FromAscii( (const char*)entry->entry.data.name ) );
	}
}

s32 FolderMemoryCard::IsPresent() {
	return m_isEnabled;
}

void FolderMemoryCard::GetSizeInfo( PS2E_McdSizeInfo& outways ) {
	outways.SectorSize = PageSize;
	outways.EraseBlockSizeInSectors = BlockSize / PageSize;
	outways.McdSizeInSectors = GetSizeInClusters() * 2;

	u8 *pdata = (u8*)&outways.McdSizeInSectors;
	outways.Xor = 18;
	outways.Xor ^= pdata[0] ^ pdata[1] ^ pdata[2] ^ pdata[3];
}

bool FolderMemoryCard::IsPSX() {
	return false;
}

u8* FolderMemoryCard::GetSystemBlockPointer( const u32 adr ) {
	const u32 block = adr / BlockSizeRaw;
	const u32 page = adr / PageSizeRaw;
	const u32 offset = adr % PageSizeRaw;
	const u32 cluster = adr / ClusterSizeRaw;

	const u32 startDataCluster = m_superBlock.data.alloc_offset;
	const u32 endDataCluster = startDataCluster + m_superBlock.data.alloc_end;
	if ( cluster >= startDataCluster && cluster < endDataCluster ) {
		// trying to access a file entry?
		const u32 fatCluster = cluster - m_superBlock.data.alloc_offset;
		// if this cluster is unused according to FAT, we can assume we won't find anything
		if ( m_fat.data[0][0][fatCluster].data.used == 0 ) {
			return nullptr;
		}
		return GetFileEntryPointer( m_superBlock.data.rootdir_cluster, fatCluster, page % 2, offset );
	}

	u8* src = nullptr;
	if ( block == 0 ) {
		src = &m_superBlock.raw[page * PageSize + offset];
	} else if ( block == m_superBlock.data.backup_block1 ) {
		src = &m_backupBlock1[( page % 16 ) * PageSize + offset];
	} else if ( block == m_superBlock.data.backup_block2 ) {
		src = &m_backupBlock2.raw[( page % 16 ) * PageSize + offset];
	} else {
		// trying to access indirect FAT?
		for ( int i = 0; i < IndirectFatClusterCount; ++i ) {
			if ( cluster == m_superBlock.data.ifc_list[i] ) {
				src = &m_indirectFat.raw[i][( page % 2 ) * PageSize + offset];
				return src;
			}
		}
		// trying to access FAT?
		for ( int i = 0; i < IndirectFatClusterCount; ++i ) {
			for ( int j = 0; j < ClusterSize / 4; ++j ) {
				const u32 fatCluster = m_indirectFat.data[i][j];
				if ( fatCluster != 0xFFFFFFFFu && fatCluster == cluster ) {
					src = &m_fat.raw[i][j][( page % 2 ) * PageSize + offset];
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
	const u32 nextCluster = m_fat.data[0][0][currentCluster].data.cluster;
	if ( nextCluster != MemoryCardFatClusterNumber::LastClusterOfData ) {
		u8* ptr = GetFileEntryPointer( nextCluster, searchCluster, entryNumber, offset );
		if ( ptr != nullptr ) { return ptr; }
	}

	// check subdirectories
	for ( int i = 0; i < 2; ++i ) {
		MemoryCardFileEntry* const entry = &m_fileEntryDict[currentCluster].entries[i];
		if ( entry->IsValid() && entry->IsUsed() && entry->IsDir() && entry->entry.data.cluster != 0 ) {
			u8* ptr = GetFileEntryPointer( entry->entry.data.cluster, searchCluster, entryNumber, offset );
			if ( ptr != nullptr ) { return ptr; }
		}
	}

	return nullptr;
}

// This method is actually unused since the introduction of m_fileMetadataQuickAccess.
// I'll leave it here anyway though to show how you traverse the file system.
MemoryCardFileEntry* FolderMemoryCard::GetFileEntryFromFileDataCluster( const u32 currentCluster, const u32 searchCluster, wxFileName* fileName, const size_t originalDirCount, u32* outClusterNumber ) {
	// check both entries of the current cluster if they're the file we're searching for, and if yes return it
	for ( int i = 0; i < 2; ++i ) {
		MemoryCardFileEntry* const entry = &m_fileEntryDict[currentCluster].entries[i];
		if ( entry->IsValid() && entry->IsUsed() && entry->IsFile() ) {
			u32 fileCluster = entry->entry.data.cluster;
			u32 clusterNumber = 0;
			do {
				if ( fileCluster == searchCluster ) {
					fileName->SetName( wxString::FromAscii( (const char*)entry->entry.data.name ) );
					*outClusterNumber = clusterNumber;
					return entry;
				}
				++clusterNumber;
			} while ( ( fileCluster = m_fat.data[0][0][fileCluster].data.cluster ) != MemoryCardFatClusterNumber::LastClusterOfData );
		}
	}

	// check other clusters of this directory
	// this can probably be solved more efficiently by looping through nextClusters instead of recursively calling
	const u32 nextCluster = m_fat.data[0][0][currentCluster].data.cluster;
	if ( nextCluster != MemoryCardFatClusterNumber::LastClusterOfData ) {
		MemoryCardFileEntry* ptr = GetFileEntryFromFileDataCluster( nextCluster, searchCluster, fileName, originalDirCount, outClusterNumber );
		if ( ptr != nullptr ) { return ptr; }
	}

	// check subdirectories
	for ( int i = 0; i < 2; ++i ) {
		MemoryCardFileEntry* const entry = &m_fileEntryDict[currentCluster].entries[i];
		if ( entry->IsValid() && entry->IsUsed() && entry->IsDir() && entry->entry.data.cluster != 0 ) {
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
	const u32 page = adr / PageSizeRaw;
	const u32 offset = adr % PageSizeRaw;
	const u32 cluster = adr / ClusterSizeRaw;
	const u32 fatCluster = cluster - m_superBlock.data.alloc_offset;

	// if the cluster is unused according to FAT, just return
	if ( m_fat.data[0][0][fatCluster].data.used == 0 ) {
		return false;
	}

	// figure out which file to read from
	auto it = m_fileMetadataQuickAccess.find( fatCluster );
	if ( it != m_fileMetadataQuickAccess.end() ) {
		wxFileName fileName( m_folderName );
		const u32 clusterNumber = it->second.consecutiveCluster;
		it->second.GetPath( &fileName );
		wxFFile* file = m_lastAccessedFile.ReOpen( fileName.GetFullPath(), L"rb" );
		if ( file->IsOpened() ) {
			const u32 clusterOffset = ( page % 2 ) * PageSize + offset;
			const u32 fileOffset = clusterNumber * ClusterSize + clusterOffset;

			if ( fileOffset != file->Tell() ) {
				file->Seek( fileOffset );
			}
			size_t bytesRead = file->Read( dest, dataLength );

			// if more bytes were requested than actually exist, fill the rest with 0xFF
			if ( bytesRead < dataLength ) {
				memset( &dest[bytesRead], 0xFF, dataLength - bytesRead );
			}

			return bytesRead > 0;
		}
	}

	return false;
}

s32 FolderMemoryCard::Read( u8 *dest, u32 adr, int size ) {
	const u32 block = adr / BlockSizeRaw;
	const u32 page = adr / PageSizeRaw;
	const u32 offset = adr % PageSizeRaw;
	const u32 cluster = adr / ClusterSizeRaw;
	const u32 end = offset + size;

	if ( end > PageSizeRaw ) {
		// is trying to read more than one page at a time
		// do this recursively so that each function call only has to care about one page
		const u32 toNextPage = PageSizeRaw - offset;
		Read( dest + toNextPage, adr + toNextPage, size - toNextPage );
		size = toNextPage;
	}

	if ( offset < PageSize ) {
		// is trying to read (part of) an actual data block
		const u32 dataOffset = 0;
		const u32 dataLength = std::min( (u32)size, (u32)( PageSize - offset ) );

		// if we have a cache for this page, just load from that
		auto it = m_cache.find( page );
		if ( it != m_cache.end() ) {
			memcpy( dest, &it->second.raw[offset], dataLength );
		} else {
			u8* src = GetSystemBlockPointer( adr );
			if ( src != nullptr ) {
				memcpy( dest, src, dataLength );
			} else {
				if ( !ReadFromFile( dest, adr, dataLength ) ) {
					memset( dest, 0xFF, dataLength );
				}
			}
		}
	}

	if ( end > PageSize ) {
		// is trying to (partially) read the ECC
		const u32 eccOffset = PageSize - offset;
		const u32 eccLength = std::min( (u32)( size - offset ), (u32)EccSize );
		const u32 adrStart = page * 0x210u;

		u8 data[PageSize];
		Read( data, adrStart, PageSize );

		u8 ecc[EccSize];
		memset( ecc, 0xFF, EccSize );

		for ( int i = 0; i < PageSize / 0x80; ++i ) {
			FolderMemoryCard::CalculateECC( ecc + ( i * 3 ), &data[i * 0x80] );
		}

		memcpy( dest + eccOffset, ecc, eccLength );
	}

	SetTimeLastReadToNow();

	// return 0 on fail, 1 on success?
	return 1;
}

s32 FolderMemoryCard::Save( const u8 *src, u32 adr, int size ) {
	const u32 block = adr / BlockSizeRaw;
	const u32 cluster = adr / ClusterSizeRaw;
	const u32 page = adr / PageSizeRaw;
	const u32 offset = adr % PageSizeRaw;
	const u32 end = offset + size;

	if ( end > PageSizeRaw ) {
		// is trying to store more than one page at a time
		// do this recursively so that each function call only has to care about one page
		const u32 toNextPage = PageSizeRaw - offset;
		Save( src + toNextPage, adr + toNextPage, size - toNextPage );
		size = toNextPage;
	}

	if ( offset < PageSize ) {
		// is trying to store (part of) an actual data block
		const u32 dataLength = std::min( (u32)size, PageSize - offset );

		// if cache page has not yet been touched, fill it with the data from our memory card
		auto it = m_cache.find( page );
		MemoryCardPage* cachePage;
		if ( it == m_cache.end() ) {
			cachePage = &m_cache[page];
			const u32 adrLoad = page * PageSizeRaw;
			Read( &cachePage->raw[0], adrLoad, PageSize );
		} else {
			cachePage = &it->second;
		}

		// then just write to the cache
		memcpy( &cachePage->raw[offset], src, dataLength );

		SetTimeLastWrittenToNow();
	}

	return 1;
}

void FolderMemoryCard::NextFrame() {
	if ( m_framesUntilFlush > 0 && --m_framesUntilFlush == 0 ) {
		Flush();
		m_lastAccessedFile.Close();
	}
}

void FolderMemoryCard::Flush() {
	if ( m_cache.empty() ) { return; }

	Console.WriteLn( L"(FolderMcd) Writing data for slot %u to file system...", m_slot );
	const u64 timeFlushStart = wxGetLocalTimeMillis().GetValue();

	// first write the superblock if necessary
	FlushBlock( 0 );
	if ( !IsFormatted() ) { return; }

	// check if we were interrupted in the middle of a save operation, if yes abort
	FlushBlock( m_superBlock.data.backup_block1 );
	FlushBlock( m_superBlock.data.backup_block2 );
	if ( m_backupBlock2.programmedBlock != 0xFFFFFFFFu ) {
		Console.Warning( L"(FolderMcd) Aborting flush of slot %u, emulation was interrupted during save process!", m_slot );
		return;
	}

	const u32 clusterCount = GetSizeInClusters();
	const u32 pageCount = clusterCount * 2;

	// then write the indirect FAT
	for ( int i = 0; i < IndirectFatClusterCount; ++i ) {
		const u32 cluster = m_superBlock.data.ifc_list[i];
		if ( cluster > 0 && cluster < clusterCount ) {
			FlushCluster( cluster );
		}
	}

	// and the FAT
	for ( int i = 0; i < IndirectFatClusterCount; ++i ) {
		for ( int j = 0; j < ClusterSize / 4; ++j ) {
			const u32 cluster = m_indirectFat.data[i][j];
			if ( cluster > 0 && cluster < clusterCount ) {
				FlushCluster( cluster );
			}
		}
	}

	// then all directory and file entries
	const u32 rootDirCluster = m_superBlock.data.rootdir_cluster;
	FlushCluster( rootDirCluster + m_superBlock.data.alloc_offset );
	MemoryCardFileEntryCluster* rootEntries = &m_fileEntryDict[rootDirCluster];
	if ( rootEntries->entries[0].IsValid() && rootEntries->entries[0].IsUsed() ) {
		FlushFileEntries( rootDirCluster, rootEntries->entries[0].entry.data.length );
	}

	// and finally, flush everything that hasn't been flushed yet
	for ( uint i = 0; i < pageCount; ++i ) {
		FlushPage( i );
	}

	m_lastAccessedFile.Close();

	const u64 timeFlushEnd = wxGetLocalTimeMillis().GetValue();
	Console.WriteLn( L"(FolderMcd) Done! Took %u ms.", timeFlushEnd - timeFlushStart );
}

void FolderMemoryCard::FlushPage( const u32 page ) {
	auto it = m_cache.find( page );
	if ( it != m_cache.end() ) {
		WriteWithoutCache( &it->second.raw[0], page * PageSizeRaw, PageSize );
		m_cache.erase( it );
	}
}

void FolderMemoryCard::FlushCluster( const u32 cluster ) {
	const u32 page = cluster * 2;
	FlushPage( page );
	FlushPage( page + 1 );
}

void FolderMemoryCard::FlushBlock( const u32 block ) {
	const u32 page = block * 16;
	for ( int i = 0; i < 16; ++i ) {
		FlushPage( page + i );
	}
}

void FolderMemoryCard::FlushFileEntries( const u32 dirCluster, const u32 remainingFiles, const wxString& dirPath, MemoryCardFileMetadataReference* parent ) {
	// flush the current cluster
	FlushCluster( dirCluster + m_superBlock.data.alloc_offset );

	// if either of the current entries is a subdir, flush that too
	MemoryCardFileEntryCluster* entries = &m_fileEntryDict[dirCluster];
	const u32 filesInThisCluster = std::min( remainingFiles, 2u );
	for ( unsigned int i = 0; i < filesInThisCluster; ++i ) {
		MemoryCardFileEntry* entry = &entries->entries[i];
		if ( entry->IsValid() && entry->IsUsed() && entry->IsDir() ) {
			const u32 cluster = entry->entry.data.cluster;
			if ( cluster > 0 ) {
				const wxString subDirName = wxString::FromAscii( (const char*)entry->entry.data.name );
				const wxString subDirPath = dirPath + L"/" + subDirName;

				// if this directory has nonstandard metadata, write that to the file system
				wxFileName metaFileName( m_folderName.GetFullPath() + subDirPath + L"/_pcsx2_meta_directory" );
				if ( entry->entry.data.mode != MemoryCardFileEntry::DefaultDirMode || entry->entry.data.attr != 0 ) {
					if ( !metaFileName.DirExists() ) {
						metaFileName.Mkdir();
					}
					wxFFile metaFile( metaFileName.GetFullPath(), L"wb" );
					if ( metaFile.IsOpened() ) {
						metaFile.Write( entry->entry.raw, 0x40 );
						metaFile.Close();
					}
				} else {
					// if metadata is standard make sure to remove a possibly existing metadata file
					if ( metaFileName.FileExists() ) {
						wxRemoveFile( metaFileName.GetFullPath() );
					}
				}

				MemoryCardFileMetadataReference* dirRef = AddDirEntryToMetadataQuickAccess( entry, parent );

				FlushFileEntries( cluster, entry->entry.data.length, subDirPath, dirRef );
			}
		} else if ( entry->IsValid() && entry->IsUsed() && entry->IsFile() ) {
			AddFileEntryToMetadataQuickAccess( entry, parent );
		}
	}

	// continue to the next cluster of this directory
	const MemoryCardFatClusterNumber nextCluster = m_fat.data[0][0][dirCluster];
	if ( nextCluster.data.cluster != MemoryCardFatClusterNumber::LastClusterOfData ) {
		FlushFileEntries( nextCluster.data.cluster, remainingFiles - 2, dirPath, parent );
	}
}

s32 FolderMemoryCard::WriteWithoutCache( const u8 *src, u32 adr, int size ) {
	const u32 block = adr / BlockSizeRaw;
	const u32 cluster = adr / ClusterSizeRaw;
	const u32 page = adr / PageSizeRaw;
	const u32 offset = adr % PageSizeRaw;
	const u32 end = offset + size;

	if ( end > PageSizeRaw ) {
		// is trying to store more than one page at a time
		// do this recursively so that each function call only has to care about one page
		const u32 toNextPage = PageSizeRaw - offset;
		Save( src + toNextPage, adr + toNextPage, size - toNextPage );
		size = toNextPage;
	}

	if ( offset < PageSize ) {
		// is trying to store (part of) an actual data block
		const u32 dataLength = std::min( (u32)size, PageSize - offset );

		u8* dest = GetSystemBlockPointer( adr );
		if ( dest != nullptr ) {
			memcpy( dest, src, dataLength );
		} else {
			WriteToFile( src, adr, dataLength );
		}
	}

	if ( end > PageSize ) {
		// is trying to store ECC
		// simply ignore this, is automatically generated when reading
	}

	// return 0 on fail, 1 on success?
	return 1;
}

bool FolderMemoryCard::WriteToFile( const u8* src, u32 adr, u32 dataLength ) {
	const u32 cluster = adr / ClusterSizeRaw;
	const u32 page = adr / PageSizeRaw;
	const u32 offset = adr % PageSizeRaw;
	const u32 fatCluster = cluster - m_superBlock.data.alloc_offset;

	// if the cluster is unused according to FAT, just skip all this, we're not gonna find anything anyway
	if ( m_fat.data[0][0][fatCluster].data.used == 0 ) {
		return false;
	}

	// figure out which file to write to
	auto it = m_fileMetadataQuickAccess.find( fatCluster );
	if ( it != m_fileMetadataQuickAccess.end() ) {
		wxFileName fileName( m_folderName );
		const MemoryCardFileEntry* const entry = it->second.entry;
		const u32 clusterNumber = it->second.consecutiveCluster;
		it->second.GetPath( &fileName );
		wxFFile* file = m_lastAccessedFile.ReOpen( fileName.GetFullPath(), L"r+b" );
		if ( file->IsOpened() ) {
			const u32 clusterOffset = ( page % 2 ) * PageSize + offset;
			const u32 fileSize = entry->entry.data.length;
			const u32 fileOffsetStart = std::min( clusterNumber * ClusterSize + clusterOffset, fileSize );;
			const u32 fileOffsetEnd = std::min( fileOffsetStart + dataLength, fileSize );
			const u32 bytesToWrite = fileOffsetEnd - fileOffsetStart;

			wxFileOffset actualFileSize = file->Length();
			if ( actualFileSize < fileOffsetStart ) {
				file->Seek( actualFileSize );
				const u32 diff = fileOffsetStart - actualFileSize;
				u8 temp = 0xFF;
				for ( u32 i = 0; i < diff; ++i ) {
					file->Write( &temp, 1 );
				}
			}

			const wxFileOffset fileOffset = file->Tell();
			if ( fileOffset != fileOffsetStart ) {
				file->Seek( fileOffsetStart );
			}
			if ( bytesToWrite > 0 ) {
				file->Write( src, bytesToWrite );
			}
		} else {
			return false;
		}

		// separately write metadata of file if it's nonstandard
		fileName.AppendDir( L"_pcsx2_meta" );
		if ( entry->entry.data.mode != MemoryCardFileEntry::DefaultFileMode || entry->entry.data.attr != 0 ) {
			if ( !fileName.DirExists() ) {
				fileName.Mkdir();
			}
			wxFFile metaFile( fileName.GetFullPath(), L"wb" );
			if ( metaFile.IsOpened() ) {
				metaFile.Write( entry->entry.raw, 0x40 );
				metaFile.Close();
			}
		} else {
			// if metadata is standard remove metadata file if it exists
			if ( fileName.FileExists() ) {
				wxRemoveFile( fileName.GetFullPath() );
				
				// and remove the metadata dir if it's now empty
				wxDir metaDir( fileName.GetPath() );
				if ( metaDir.IsOpened() && !metaDir.HasFiles() ) {
					wxRmdir( fileName.GetPath() );
				}
			}
		}

		return true;
	}

	return false;
}

s32 FolderMemoryCard::EraseBlock( u32 adr ) {
	const u32 block = adr / BlockSizeRaw;

	u8 eraseData[PageSize];
	memset( eraseData, 0xFF, PageSize );
	for ( int page = 0; page < 16; ++page ) {
		const u32 adr = block * BlockSizeRaw + page * PageSizeRaw;
		Save( eraseData, adr, PageSize );
	}

	// return 0 on fail, 1 on success?
	return 1;
}

u64 FolderMemoryCard::GetCRC() {
	// Since this is just used as integrity check for savestate loading,
	// give a timestamp of the last time the memory card was written to
	return m_timeLastWritten;
}

void FolderMemoryCard::SetSlot( uint slot ) {
	pxAssert( slot < 8 );
	m_slot = slot;
}

u32 FolderMemoryCard::GetSizeInClusters() {
	const u32 clusters = m_superBlock.data.clusters_per_card;
	if ( clusters > 0 && clusters < UINT32_MAX ) {
		return clusters;
	} else {
		return TotalClusters;
	}
}

void FolderMemoryCard::SetSizeInClusters( u32 clusters ) {
	m_superBlock.data.clusters_per_card = clusters;
	
	const u32 alloc_offset = clusters / 0x100 + 9;
	m_superBlock.data.alloc_offset = alloc_offset;
	m_superBlock.data.alloc_end = clusters - 0x10 - alloc_offset;

	const u32 blocks = clusters / 8;
	m_superBlock.data.backup_block1 = blocks - 1;
	m_superBlock.data.backup_block2 = blocks - 2;
}

void FolderMemoryCard::SetSizeInMB( u32 megaBytes ) {
	SetSizeInClusters( ( megaBytes * 1024 * 1024 ) / ClusterSize );
}

void FolderMemoryCard::SetTimeLastReadToNow() {
	m_framesUntilFlush = FramesAfterWriteUntilFlush;
}

void FolderMemoryCard::SetTimeLastWrittenToNow() {
	m_timeLastWritten = wxGetLocalTimeMillis().GetValue();
	m_framesUntilFlush = FramesAfterWriteUntilFlush;
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


FileAccessHelper::FileAccessHelper() {
	m_file = nullptr;
}

FileAccessHelper::~FileAccessHelper() {
	this->Close();
}

wxFFile* FileAccessHelper::Open( const wxString& filename, const wxString& mode ) {
	this->Close();

	wxFileName fn( filename );
	if ( !fn.FileExists() ) {
		if ( !fn.DirExists() ) {
			fn.Mkdir();
		}
		wxFFile createEmptyFile( filename, L"wb" );
		createEmptyFile.Close();
	}

	m_file = new wxFFile( filename, mode );
	m_filename = filename;
	m_mode = mode;
	return m_file;
}

wxFFile* FileAccessHelper::ReOpen( const wxString& filename, const wxString& mode ) {
	if ( m_file && mode == m_mode && filename == m_filename ) {
		return m_file;
	} else {
		return this->Open( filename, mode );
	}
}

void FileAccessHelper::Close() {
	if ( m_file ) {
		m_file->Close();
		delete m_file;
		m_file = nullptr;
	}
}


FolderMemoryCardAggregator::FolderMemoryCardAggregator() {
	for ( uint i = 0; i < TotalCardSlots; ++i ) {
		m_cards[i].SetSlot( i );
	}
}

void FolderMemoryCardAggregator::Open() {
	for ( int i = 0; i < TotalCardSlots; ++i ) {
		m_cards[i].Open( m_enableFiltering, m_lastKnownFilter );
	}
}

void FolderMemoryCardAggregator::Close() {
	for ( int i = 0; i < TotalCardSlots; ++i ) {
		m_cards[i].Close();
	}
}

void FolderMemoryCardAggregator::SetFiltering( const bool enableFiltering ) {
	m_enableFiltering = enableFiltering;
}

s32 FolderMemoryCardAggregator::IsPresent( uint slot ) {
	return m_cards[slot].IsPresent();
}

void FolderMemoryCardAggregator::GetSizeInfo( uint slot, PS2E_McdSizeInfo& outways ) {
	m_cards[slot].GetSizeInfo( outways );
}

bool FolderMemoryCardAggregator::IsPSX( uint slot ) {
	return m_cards[slot].IsPSX();
}

s32 FolderMemoryCardAggregator::Read( uint slot, u8 *dest, u32 adr, int size ) {
	return m_cards[slot].Read( dest, adr, size );
}

s32 FolderMemoryCardAggregator::Save( uint slot, const u8 *src, u32 adr, int size ) {
	return m_cards[slot].Save( src, adr, size );
}

s32 FolderMemoryCardAggregator::EraseBlock( uint slot, u32 adr ) {
	return m_cards[slot].EraseBlock( adr );
}

u64 FolderMemoryCardAggregator::GetCRC( uint slot ) {
	return m_cards[slot].GetCRC();
}

void FolderMemoryCardAggregator::NextFrame( uint slot ) {
	m_cards[slot].NextFrame();
}

void FolderMemoryCardAggregator::ReIndex( uint slot, const bool enableFiltering, const wxString& filter ) {
	m_cards[slot].Close();
	m_cards[slot].Open( enableFiltering, filter );

	SetFiltering( enableFiltering );
	m_lastKnownFilter = filter;
}

