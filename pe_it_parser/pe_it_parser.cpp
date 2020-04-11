#include <Windows.h>
#include <iostream>

using namespace std;

// Function declaration
void outHelp();
void outError();
bool isPE(PIMAGE_NT_HEADERS pefile);

int main(int argc, char** argv)
{
	printf(
		"PE Import Table parser v1.0 by Akenth0r\n"
		"You can find me at www.github.com/akenth0r\n\n"
	);

	if (argc < 2)
	{
		outHelp();
		return -1;
	}
	// Open the file
	printf("* Open file...\n");
	HANDLE hFile = CreateFileA(
		argv[1],						// Name of the file
		GENERIC_READ | GENERIC_WRITE,	// Access rights
		NULL,						    // Share mode
		NULL,							// Security attribs				
		OPEN_EXISTING,					// Open only if file exists
		FILE_ATTRIBUTE_NORMAL,			// File haven't any attributes set
		NULL							// Ignoring this parameter when open file
	);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		outError();
		return -1;
	}
	
	// Map file into process memory
	HANDLE hFileMap = CreateFileMapping(
		hFile,							// File handle
		NULL,							// Security attribs
		PAGE_READWRITE | SEC_IMAGE,		// Page access
		0,								// High word max size
		0,								// Low word max size
		NULL							// Name
	);
	if (!hFileMap)
	{
		outError();
		return -1;
	}

	// Create file view
	LPVOID lpFileView = MapViewOfFile(
		hFileMap,				// Mapping handle
		FILE_MAP_ALL_ACCESS,	// Access
		0,						// File offset high word
		0,						// File offset low word
		0						// View all the file
	);
	if (!lpFileView)
	{
		outError();
		return -1;
	}

	// Check if it's MZ
	printf("* Check if it's PE...\n");
	PIMAGE_NT_HEADERS peFile = (PIMAGE_NT_HEADERS)lpFileView;
	if (!isPE(peFile))
	{
		printf("The file is not a file of PE format\n");
		return -1;
	};
	
	// Get file header
	PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)((DWORD)((DWORD)peFile + *(DWORD*)((DWORD)(peFile)+0x3c)) + 4);

	// Get optional header
	PIMAGE_OPTIONAL_HEADER optHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)((DWORD)peFile + *(DWORD*)((DWORD)(peFile)+0x3c)) + (DWORD)24);

	// Get Data Directory array
	PIMAGE_DATA_DIRECTORY dataDirectory = optHeader->DataDirectory;

	// Get import directory
	IMAGE_DATA_DIRECTORY importDirectory = dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// Get first descriptor of import table
	PIMAGE_IMPORT_DESCRIPTOR iDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)peFile + (DWORD)importDirectory.VirtualAddress);
	
	// Parse this shit!
	for (; iDesc->FirstThunk; iDesc++)
	{
		printf("=================================\n"
			"Dll Name: %s\n",
			(char*)((DWORD)peFile + DWORD(iDesc->Name)));
		PIMAGE_THUNK_DATA origThunk = PIMAGE_THUNK_DATA((DWORD)peFile + (DWORD)iDesc->FirstThunk);
		
		// Functions
		for (; origThunk->u1.AddressOfData; origThunk++)
		{
			auto data = origThunk->u1.AddressOfData;
			if (data & IMAGE_ORDINAL_FLAG)
				printf("Ordinal: %X\n", data & ~IMAGE_ORDINAL_FLAG);
			else
				printf("\t%s\n", (char*)((DWORD)peFile + (DWORD)origThunk->u1.AddressOfData) + 2);

		}
		printf("=================================\n");
	}

	UnmapViewOfFile(lpFileView);
	CloseHandle(hFileMap);
	CloseHandle(hFile);
	printf("Done.\n");
	return 0;
}


void outHelp()
{
	printf(
		"To use this utility you need to enter a name of the file as argument\n"
		"In cmd it looks like:\n"
		"> pe_it_parser file_name"
	);
}

void outError()
{
	printf("Error: cannot open the file");
}

bool isPE(PIMAGE_NT_HEADERS pefile)
{
	if ((WORD)pefile->Signature != IMAGE_DOS_SIGNATURE)
		return false;
	DWORD pe_signature = *(DWORD*)((DWORD)pefile + *(DWORD*)((DWORD)(pefile)+0x3c));
	if (pe_signature != 0x4550)
		return false;
	
	return true;
}