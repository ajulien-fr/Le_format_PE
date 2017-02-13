#include <windows.h>
#include <stdio.h>

typedef FILE *PFILE;

typedef struct _S_PE
{
	PFILE pfile;
	IMAGE_DOS_HEADER iDosHeader;
	IMAGE_NT_HEADERS iNtHeaders;
	PIMAGE_SECTION_HEADER piSectionHeader;
}S_PE, *PS_PE;

void ListExportedFunctions(PS_PE pspe);

void Init(PS_PE pspe);
DWORD RvaToOffset(PS_PE pspe, DWORD rva);
void ReadCstring(PS_PE pspe, char *name);

int main(int argc, char *argv[])
{
	S_PE spe;

	if (argc != 2)
	{
		printf("USAGE: ListExportedFunctions.exe <fichier>\n");
		printf("EXAMPLE: ListExportedFunctions.exe C:\\Windows\\System32\\kernel32.dll\n");
		printf("\n");
		system("PAUSE");
		exit(1);
	}

	memset(&spe, 0, sizeof(S_PE));

	spe.pfile = fopen(argv[1], "rb");

	if (spe.pfile == NULL)
	{
		printf("ERREUR : impossible d'ouvrir %s\n", argv[1]);
		exit(1);
	}

	Init(&spe);

	ListExportedFunctions(&spe);

	fclose(spe.pfile);

	return 0;
}

void Init(S_PE *pspe)
{
	// On lit l'en-tête DOS : 
	fread(&pspe->iDosHeader, sizeof(IMAGE_DOS_HEADER), 1, pspe->pfile);

	// On check la signature : 
	if (pspe->iDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("ERREUR : le fichier n'est pas valide!n");
		exit(1);
	}

	// On se positionne à l'offset de l'en-tête NT : 
	fseek(pspe->pfile, pspe->iDosHeader.e_lfanew, SEEK_SET);

	// On lit l'en-tête NT : 
	fread(&pspe->iNtHeaders, sizeof(IMAGE_NT_HEADERS), 1, pspe->pfile);

	// On check la signature : 
	if (pspe->iNtHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		printf("ERREUR : le fichier n'est pas valide!\n");
		exit(1);
	}

	// On lit toutes les sections : 
	pspe->piSectionHeader = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * pspe->iNtHeaders.FileHeader.NumberOfSections);

	for (unsigned i = 0; i < pspe->iNtHeaders.FileHeader.NumberOfSections; i++)
	{
		fread(&pspe->piSectionHeader[i], sizeof(IMAGE_SECTION_HEADER), 1, pspe->pfile);
	}
}

void ListExportedFunctions(PS_PE pspe)
{
	IMAGE_EXPORT_DIRECTORY iExportDir;
	DWORD namePos = 0;
	WORD ordinal = 0;
	DWORD address = 0;
	char name[1024];

	// On se positionne à la table des fonctions exportées : 
	fseek(pspe->pfile, RvaToOffset(pspe, pspe->iNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), SEEK_SET);

	// On lit la structure IMAGE_EXPORT_DIRECTORY : 
	fread(&iExportDir, sizeof(IMAGE_EXPORT_DIRECTORY), 1, pspe->pfile);

	printf("NumberOfNames: %d\n\n", iExportDir.NumberOfNames);

	printf("ordinal / index -- name -- address\n\n");

	for (DWORD i = 0; i < iExportDir.NumberOfNames; i++)
	{
		// Ordinal
		fseek(pspe->pfile, RvaToOffset(pspe, iExportDir.AddressOfNameOrdinals) + i * sizeof(WORD), SEEK_SET);
		fread(&ordinal, sizeof(WORD), 1, pspe->pfile);
		ordinal += (WORD)iExportDir.Base;
		printf("%d -- ", ordinal);

		// Name
		fseek(pspe->pfile, RvaToOffset(pspe, iExportDir.AddressOfNames) + i * sizeof(DWORD), SEEK_SET);
		fread(&namePos, sizeof(DWORD), 1, pspe->pfile);
		fseek(pspe->pfile, RvaToOffset(pspe, namePos), SEEK_SET);
		ReadCstring(pspe, name);
		printf("%s -- ", name);

		// Address
		fseek(pspe->pfile, RvaToOffset(pspe, iExportDir.AddressOfFunctions) + (ordinal - iExportDir.Base) * sizeof(DWORD), SEEK_SET);
		fread(&address, sizeof(DWORD), 1, pspe->pfile);
		printf("%.8X", address);

		// Is forwarded ?
		if (pspe->iNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress < address
			&& address < pspe->iNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + pspe->iNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		{
			fseek(pspe->pfile, RvaToOffset(pspe, address), SEEK_SET);
			ReadCstring(pspe, name);
			printf(" (forwarder -> %s)\n", name);
		}
		else printf("\n");
	}
}

DWORD RvaToOffset(PS_PE pspe, DWORD rva)
{
	for (WORD i = 0; i < pspe->iNtHeaders.FileHeader.NumberOfSections; i++)
	{
		// La RVA est-elle dans cette section?
		if ((rva >= pspe->piSectionHeader[i].VirtualAddress) && (rva < pspe->piSectionHeader[i].VirtualAddress + pspe->piSectionHeader[i].SizeOfRawData))
		{
			rva -= pspe->piSectionHeader[i].VirtualAddress;
			rva += pspe->piSectionHeader[i].PointerToRawData;

			return rva;
		}
	}

	return -1;
}

void ReadCstring(PS_PE pspe, char *name)
{
	DWORD n = 0;

	do
	{
		fread(name + n, sizeof(char), 1, pspe->pfile);
		n++;
	} while (name[n - 1] != 0 && n < 1023);

	name[n] = 0;
}
