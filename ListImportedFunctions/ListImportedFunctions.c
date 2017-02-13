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

void ListImportedFunctions(PS_PE pspe);

void Init(PS_PE pspe);
DWORD RvaToOffset(PS_PE pspe, DWORD rva);
void ReadCstring(PS_PE pspe, char *name);

int main(int argc, char *argv[])
{
	S_PE spe;

	if (argc != 2)
	{
		printf("USAGE: ListImportedFunctions.exe <fichier>\n");
		printf("EXAMPLE: ListImportedFunctions.exe C:\\Windows\\System32\\kernel32.dll\n");
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

	ListImportedFunctions(&spe);

	printf("\n");

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
		printf("ERREUR : le fichier n'est pas valide!\n");
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

DWORD RvaToOffset(PS_PE pspe, DWORD rva)
{
	for (WORD i = 0; i < pspe->iNtHeaders.FileHeader.NumberOfSections; i++)
	{
		// La RVA est-elle dans cette section ?
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

void ListImportedFunctions(PS_PE pspe)
{
	IMAGE_IMPORT_DESCRIPTOR iImportDesc;
	char name[1024];
	DWORD thunkData = 0;
	WORD hint = 0;

	// On se positionne a la table des fonctions importées : 
	DWORD offset = RvaToOffset(pspe, pspe->iNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (DWORD i = 0;; i++)
	{
		// On se place à la structure IMAGE_IMPORT_DESCRIPTOR qu'il nous faut : 
		fseek(pspe->pfile, offset + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), SEEK_SET);

		// On la lit : 
		fread(&iImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pspe->pfile);

		// Est-ce la dernière IMAGE_IMPORT_DESCRIPTOR?
		if ((iImportDesc.Characteristics == 0) && (iImportDesc.FirstThunk == 0) && (iImportDesc.ForwarderChain == 0)
			&& (iImportDesc.Name == 0) && (iImportDesc.OriginalFirstThunk == 0) && (iImportDesc.TimeDateStamp == 0)) break;

		// On va à la RVA du nom de la dll : 
		fseek(pspe->pfile, RvaToOffset(pspe, iImportDesc.Name), SEEK_SET);

		// On lit le nom de la dll : 
		ReadCstring(pspe, name);
		printf("[+] %s\n", name);

		for (DWORD j = 0;; j++)
		{
			// On se place au Thunk qu'il nous faut : 
			if (iImportDesc.OriginalFirstThunk != 0)
				fseek(pspe->pfile, RvaToOffset(pspe, iImportDesc.OriginalFirstThunk) + j * sizeof(DWORD), SEEK_SET);
			else
				fseek(pspe->pfile, RvaToOffset(pspe, iImportDesc.FirstThunk) + j * sizeof(DWORD), SEEK_SET);

			// On le lit : 
			fread(&thunkData, sizeof(DWORD), 1, pspe->pfile);

			// Est-ce le dernier?
			if (thunkData == 0) break;

			// Est-ce une fonction importée par son nom?
			if ((thunkData & IMAGE_ORDINAL_FLAG32) == 0)
			{
				// On va à la RVA sur IMAGE_IMPORT_BY_NAME : 
				fseek(pspe->pfile, RvaToOffset(pspe, thunkData), SEEK_SET);

				// On lit le Hint : 
				fread(&hint, sizeof(WORD), 1, pspe->pfile);

				printf("    %d - ", hint);

				// On lit le nom : 
				ReadCstring(pspe, name);
				printf("%s\n", name);
			}
		}
	}
}
