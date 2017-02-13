#include <windows.h>
#include <stdio.h>

void DumpTextSection(IMAGE_SECTION_HEADER iSectionHeader, FILE *pfile);

int main(int argc, char *argv[])
{
	IMAGE_DOS_HEADER iDosHeader;
	IMAGE_NT_HEADERS iNtHeaders;
	IMAGE_SECTION_HEADER iSectionHeader;
	FILE *pfile = NULL;

	if (argc != 2)
	{
		printf("USAGE: DumpTextSection.exe <fichier>\n");
		printf("EXAMPLE: DumpTextSection.exe C:\\Windows\\System32\\kernel32.dll\n");
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
		// On lit une section : 
		fread(&iSectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, pfile);

		// Est-ce la section .text?
		if (!strcmp((char*)iSectionHeader.Name, ".text"))
		{
			DumpTextSection(iSectionHeader, pfile);
			break;
		}
	}

	printf("\n");

	return 0;
}

void DumpTextSection(IMAGE_SECTION_HEADER iSectionHeader, FILE *pfile)
{
	BYTE by = 0;
	DWORD i;
	unsigned u = 0;

	// On se place au debut de la section : 
	fseek(pfile, iSectionHeader.PointerToRawData, SEEK_SET);

	for (i = 0, u = 0; i < iSectionHeader.Misc.VirtualSize; i++, u++)
	{
		// On lit byte par byte : 
		fread(&by, sizeof(BYTE), 1, pfile);

		if (u == 16)
		{
			printf("\n");
			u = 0;
		}

		printf("%.2X ", by);
	}
}
