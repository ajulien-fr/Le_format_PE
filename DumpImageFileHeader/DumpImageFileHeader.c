#include <windows.h>
#include <stdio.h>
#include <time.h>

typedef struct
{
	WORD flag;
	PCHAR name;
}CHARACTERISTICS;

CHARACTERISTICS arrCharacteristics[] =
{
	{ IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED" },
	{ IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE" },
	{ IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED" },
	{ IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED" },
	{ IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESIVE_WS_TRIM" },
	{ IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE" },
	{ IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO" },
	{ IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE" },
	{ IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED" },
	{ IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP" },
	{ IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP" },
	{ IMAGE_FILE_SYSTEM, "SYSTEM" },
	{ IMAGE_FILE_DLL, "DLL" },
	{ IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY" },
	{ IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI" }
};

void DumpImageFileHeader(IMAGE_FILE_HEADER iFileHeader);

int main(int argc, char *argv[])
{
	IMAGE_DOS_HEADER iDosHeader;
	IMAGE_NT_HEADERS iNtHeaders;
	FILE *pfile = NULL;

	if (argc != 2)
	{
		printf("USAGE: DumpImageFileHeader.exe <fichier>\n");
		printf("EXAMPLE: DumpImageFileHeader.exe C:\\Windows\\System32\\kernel32.dll\n");
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

	DumpImageFileHeader(iNtHeaders.FileHeader);

	return 0;
}

void DumpImageFileHeader(IMAGE_FILE_HEADER iFileHeader)
{
	// Machine
	if (iFileHeader.Machine == IMAGE_FILE_MACHINE_I386)
		printf("[*] Machine: %.4X (x86)\n", iFileHeader.Machine);
	else if (iFileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		printf("[*] Machine: %.4X (x64)\n", iFileHeader.Machine);
	else
		printf("[*] Machine: %.4X (ni x86 ni x64)\n", iFileHeader.Machine);

	printf("\n");

	// NumberOfSections
	printf("[*] NumberOfSections: %hu\n", iFileHeader.NumberOfSections);

	printf("\n");

	// TimeDateStamp
	printf("[*] TimeDateStamp: %lu\n", iFileHeader.TimeDateStamp);
	printf("    %s", ctime((time_t*)&iFileHeader.TimeDateStamp));

	printf("\n");

	// PointerToSymbolTable
	printf("[*] PointerToSymbolTable: %.8X\n", iFileHeader.PointerToSymbolTable);

	printf("\n");

	// NumberOfSymbols
	printf("[*] NumberOfSymbols: %lu\n", iFileHeader.NumberOfSymbols);

	printf("\n");

	// SizeOfOptionalHeader
	printf("[*] SizeOfOptionalHeader: %hu\n", iFileHeader.SizeOfOptionalHeader);

	printf("\n");

	// Characteristics
	printf("[*] Characteristics: %.4X\n", iFileHeader.Characteristics);
	for (unsigned u = 0; u < sizeof(arrCharacteristics) / sizeof(CHARACTERISTICS); u++)
	{
		if (iFileHeader.Characteristics & arrCharacteristics[u].flag)
		{
			printf("    %s\n", arrCharacteristics[u].name);
		}
	}
}
