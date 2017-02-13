#include <windows.h>
#include <stdio.h>

typedef struct
{
	DWORD flag;
	PCHAR name;
}CHARACTERISTICS;

CHARACTERISTICS arrCharacteristics[] =
{
	{ IMAGE_SCN_TYPE_NO_PAD, "TYPE_NO_PAD" },
	{ IMAGE_SCN_CNT_CODE, "CNT_CODE" },
	{ IMAGE_SCN_CNT_INITIALIZED_DATA, "CNT_INITIALIZED_DATA" },
	{ IMAGE_SCN_CNT_UNINITIALIZED_DATA, "CNT_UNINITIALIZED_DATA" },
	{ IMAGE_SCN_LNK_OTHER, "LNK_OTHER" },
	{ IMAGE_SCN_LNK_INFO, "LNK_INFO" },
	{ IMAGE_SCN_LNK_REMOVE, "LNK_REMOVE" },
	{ IMAGE_SCN_LNK_COMDAT, "LNK_COMDAT" },
	{ IMAGE_SCN_NO_DEFER_SPEC_EXC, "NO_DEFER_SPEC_EXC" },
	{ IMAGE_SCN_GPREL, "GPREL" },
	{ IMAGE_SCN_MEM_FARDATA, "MEM_FARDATA" },
	{ IMAGE_SCN_MEM_PURGEABLE, "MEM_PURGEABLE" },
	{ IMAGE_SCN_MEM_16BIT, "MEM_16BIT" },
	{ IMAGE_SCN_MEM_LOCKED, "MEM_LOCKED" },
	{ IMAGE_SCN_MEM_PRELOAD, "MEM_PRELOAD" },
	{ IMAGE_SCN_ALIGN_1BYTES, "ALIGN_1BYTES" },
	{ IMAGE_SCN_ALIGN_2BYTES, "ALIGN_2BYTES" },
	{ IMAGE_SCN_ALIGN_4BYTES, "ALIGN_4BYTES" },
	{ IMAGE_SCN_ALIGN_8BYTES, "ALIGN_8BYTES" },
	{ IMAGE_SCN_ALIGN_16BYTES, "ALIGN_16BYTES" },
	{ IMAGE_SCN_ALIGN_32BYTES, "ALIGN_32BYTES" },
	{ IMAGE_SCN_ALIGN_64BYTES, "ALIGN_64BYTES" },
	{ IMAGE_SCN_ALIGN_128BYTES, "ALIGN_128BYTES" },
	{ IMAGE_SCN_ALIGN_256BYTES, "ALIGN_256BYTES" },
	{ IMAGE_SCN_ALIGN_512BYTES, "ALIGN_512BYTES" },
	{ IMAGE_SCN_ALIGN_1024BYTES, "ALIGN_1024BYTES" },
	{ IMAGE_SCN_ALIGN_2048BYTES, "ALIGN_2048BYTES" },
	{ IMAGE_SCN_ALIGN_4096BYTES, "ALIGN_4096BYTES" },
	{ IMAGE_SCN_ALIGN_8192BYTES, "ALIGN_8192BYTES" },
	{ IMAGE_SCN_ALIGN_MASK, "ALIGN_MASK" },
	{ IMAGE_SCN_LNK_NRELOC_OVFL, "LNK_NRELOC_OVFL" },
	{ IMAGE_SCN_MEM_DISCARDABLE, "MEM_DISCARDABLE" },
	{ IMAGE_SCN_MEM_NOT_CACHED, "MEM_NOT_CACHED" },
	{ IMAGE_SCN_MEM_NOT_PAGED, "MEM_NOT_PAGED" },
	{ IMAGE_SCN_MEM_SHARED, "MEM_SHARED" },
	{ IMAGE_SCN_MEM_EXECUTE, "MEM_EXECUTE" },
	{ IMAGE_SCN_MEM_READ, "MEM_READ" },
	{ IMAGE_SCN_MEM_WRITE, "MEM_WRITE" }
};

void DumpSectionsInfos(IMAGE_SECTION_HEADER iSectionHeader);

int main(int argc, char *argv[])
{
	IMAGE_DOS_HEADER iDosHeader;
	IMAGE_NT_HEADERS iNtHeaders;
	IMAGE_SECTION_HEADER iSectionHeader;
	FILE *pfile = NULL;

	if (argc != 2)
	{
		printf("USAGE: DumpSectionsInfos.exe <fichier>\n");
		printf("EXAMPLE: DumpSectionsInfos.exe C:\\Windows\\System32\\kernel32.dll\n");
		printf("\n");
		system("PAUSE");
		exit(1);
	}

	pfile = fopen(argv[1], "rb");

	if (pfile == NULL)
	{
		printf("ERREUR : impossible d'ouvrir %s\n", argv[1]);
		exit(1);
	}

	// On lit l'en-tête DOS : 
	fread(&iDosHeader, sizeof(IMAGE_DOS_HEADER), 1, pfile);

	// On check la signature : 
	if (iDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("ERREUR : le fichier n'est pas valide!\n");
		exit(1);
	}

	// On se positionne à l'offset de l'en-tête NT : 
	fseek(pfile, iDosHeader.e_lfanew, SEEK_SET);

	// On lit l'en-tête NT : 
	fread(&iNtHeaders, sizeof(IMAGE_NT_HEADERS), 1, pfile);

	// On check la signature : 
	if (iNtHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		printf("ERREUR : le fichier n'est pas valide!\n");
		exit(1);
	}

	for (WORD w = 0; w < iNtHeaders.FileHeader.NumberOfSections; w++)
	{
		// On lit une structure IMAGE_SECTION_HEADER : 
		fread(&iSectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, pfile);
		DumpSectionsInfos(iSectionHeader);
	}

	fclose(pfile);

	return 0;
}

void DumpSectionsInfos(IMAGE_SECTION_HEADER iSectionHeader)
{
	// Name
	printf("[*] Name: %s\n", iSectionHeader.Name);

	printf("\n");

	// VirtualSize : 
	printf("[*] VirtualSize: %lu\n", iSectionHeader.Misc.VirtualSize);

	printf("\n");

	// VirtualAddress : 
	printf("[*] VirtualAddress: %.8X\n", iSectionHeader.VirtualAddress);

	printf("\n");

	// SizeOfRawData : 
	printf("[*] SizeOfRawData: %lu\n", iSectionHeader.SizeOfRawData);

	printf("\n");

	// PointerToRawData : 
	printf("[*] PointerToRawData: %.8X\n", iSectionHeader.PointerToRawData);

	printf("\n");

	// PointerToRelocations : 
	printf("[*] PointerToRelocations: %.8X\n", iSectionHeader.PointerToRelocations);

	printf("\n");

	// PointerToLinenumbers : 
	printf("[*] PointerToLinenumbers: %.8X\n", iSectionHeader.PointerToLinenumbers);

	printf("\n");

	// NumberOfRelocations : 
	printf("[*] NumberOfRelocations: %hu\n", iSectionHeader.NumberOfRelocations);

	printf("\n");

	// NumberOfLinenumbers : 
	printf("[*] NumberOfLinenumbers: %hu\n", iSectionHeader.NumberOfLinenumbers);

	printf("\n");

	// Characteristics : 
	printf("[*] Characteristics: %.8X\n", iSectionHeader.Characteristics);
	for (unsigned u = 0; u < sizeof(arrCharacteristics) / sizeof(CHARACTERISTICS); u++)
	{
		if (iSectionHeader.Characteristics & arrCharacteristics[u].flag)
		{
			printf("    %s\n", arrCharacteristics[u].name);
		}
	}

	printf("\n");

	printf("    -------------------------\n\n\n");
}
