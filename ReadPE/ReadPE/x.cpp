#undef   UNICODE
#include <iostream>
#include <Windows.h>

using namespace std;

char *FileContent;

LONG TurnRvaIntoRaw(PIMAGE_NT_HEADERS temp, LONG Rva)
{
	INT NumbersOfSections = temp->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(temp);
	for (int i = 0; i < NumbersOfSections; ++i)
	{
		DWORD StartAddress = SectionHeader->VirtualAddress;
		DWORD EndAddress = StartAddress + SectionHeader->Misc.VirtualSize;
		if (Rva >= StartAddress && Rva <= EndAddress)
		{
			//cout << Rva - StartAddress + SectionHeader->PointerToRawData << endl;
			return Rva - StartAddress + SectionHeader->PointerToRawData;
		}
		++SectionHeader;
	}
	return 0;
}

bool IsPEFile(HANDLE FILE)
{
	unsigned int FileSize = GetFileSize(FILE, NULL);
	DWORD ReadFileSize;
	FileContent = new char[FileSize + 1];
	ReadFile(FILE, FileContent, FileSize, &ReadFileSize, NULL);

	IMAGE_DOS_HEADER * DosHeader = (IMAGE_DOS_HEADER *)FileContent;
	if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)(FileContent + DosHeader->e_lfanew);
		if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
			return true;
	}

	return false;
}

bool AnalyPE()
{
	IMAGE_DOS_HEADER * DosHeader = (IMAGE_DOS_HEADER *)FileContent;
	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)(FileContent + DosHeader->e_lfanew);
	/*��Ϊ�����Ѿ�ȷ������PE�ļ�������������������ȷ��һ����*/
	cout << hex;
	cout << "Ĭ�ϼ��ص�ַΪ��" << NtHeader->OptionalHeader.ImageBase << endl;
	cout << "�ڴ�ҳ���СΪ��" << NtHeader->OptionalHeader.SectionAlignment << endl;
	cout << "Ӳ�������СΪ��" << NtHeader->OptionalHeader.FileAlignment << endl;
	cout << "Ĭ�ϵĶ�ջ��С�ǣ�" << NtHeader->OptionalHeader.SizeOfStackCommit << endl;
	cout << "Ĭ�ϵĶ�ջ���ƴ�С�ǣ�" << NtHeader->OptionalHeader.SizeOfStackCommit << endl;
	cout << "���ļ���" << NtHeader->FileHeader.NumberOfSections << "������" << endl;
	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0)
		cout << "��ǰ�ļ�����TLS����ȷ�Ϻ��ٴ򿪣���TLS��ʱ����Ϊ����/�ӿǴ�������ڵأ���" << endl;
	cout << "----------------------------------------------------------------" << endl;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(NtHeader);
	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++pSection)
	{
		cout << "��" << i + 1 << "������������ǣ�" << pSection->Name << endl;
		cout << "���������ڴ��е���ʼ��ַ�ǣ�" << pSection->VirtualAddress << endl;
		cout << "���������ڴ��еĴ�СΪ��" << pSection->Misc.VirtualSize << endl;
		cout << "���������ļ��е���ʼ��" << pSection->PointerToRawData << endl;
		cout << "�������ڴ����еĴ�СΪ��" << pSection->SizeOfRawData << endl;
	}
	cout << "----------------------------------------------------------------" << endl << endl;

	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
	{
		IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)(FileContent + TurnRvaIntoRaw(NtHeader, NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
		for (; ImportDescriptor->Name != NULL; ++ImportDescriptor)
		{
			cout << (char *)(FileContent + TurnRvaIntoRaw(NtHeader, ImportDescriptor->Name)) << "�е��뺯��Ϊ��" << endl;
			IMAGE_THUNK_DATA *ThunkData = (IMAGE_THUNK_DATA *)(FileContent + TurnRvaIntoRaw(NtHeader, ImportDescriptor->FirstThunk));
			for (; ThunkData->u1.Ordinal != 0; ThunkData++)
			{
				if (ThunkData->u1.Ordinal & 0x80000000)				//�����λΪ1����Ϊ������룬��������������
					cout << "�������Ϊ��" << (ThunkData->u1.Ordinal & 0x0000ffff) << endl;
				else
				{
					IMAGE_IMPORT_BY_NAME *ImportName = (IMAGE_IMPORT_BY_NAME *)(FileContent + TurnRvaIntoRaw(NtHeader,ThunkData->u1.AddressOfData));
					cout << "��������Ϊ��" << ImportName->Name << endl;
				}
			}
			cout << "----------------------------------------------------------------" << endl;
		}
	}

	return true;
}

bool LoadPE()
{
	IMAGE_DOS_HEADER * DosHeader = (IMAGE_DOS_HEADER *)FileContent;
	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)(FileContent + DosHeader->e_lfanew);
	
	DWORD ImageSize = NtHeader->OptionalHeader.SizeOfImage;							//�������ڴ��еĴ�С��
	char *PE = new char[ImageSize];
	
	DWORD HeaderSize = NtHeader->OptionalHeader.SizeOfHeaders;						//����HEADERS�Ĵ�С��
	memcpy(PE, FileContent, HeaderSize);

	DWORD EntryPoint = NtHeader->OptionalHeader.AddressOfEntryPoint;				//�������ڵ�ַ��RVA��

	DWORD ImageBase = NtHeader->OptionalHeader.ImageBase;							//������صĻ�ַ

	IMAGE_SECTION_HEADER * SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
		memcpy(PE + SectionHeader->VirtualAddress, FileContent + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);

	/*���˸��ƺ������еĶ�����������Ҫ�ѵ�����滻��*/

	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
	{
		IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)(PE + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		for (; ImportDescriptor->Name != NULL; ++ImportDescriptor)
		{
			HMODULE hModule = LoadLibraryA((char *)(PE + ImportDescriptor->Name));

			if (hModule == NULL)
			{
				cout << "LoadLibraryʧ�ܣ�" << endl;
				return false;
			}

			IMAGE_THUNK_DATA *ThunkData = (IMAGE_THUNK_DATA *)(PE + ImportDescriptor->FirstThunk);
			for (; ThunkData->u1.Ordinal != 0; ThunkData++)
			{
				if (ThunkData->u1.Ordinal & 0x80000000)				//�����λΪ1����Ϊ������룬��������������
				{
					ThunkData->u1.Function = (DWORD)(GetProcAddress(hModule, (char*)(ThunkData->u1.Ordinal & 0x0000ffff)));
				}
				else
				{
					IMAGE_IMPORT_BY_NAME *ImportName = (IMAGE_IMPORT_BY_NAME *)(PE + ThunkData->u1.AddressOfData);
					ThunkData->u1.Function = (DWORD)(GetProcAddress(hModule, ImportName->Name));
				}
			}
			FreeLibrary(hModule);
		}
	}

	/*���ˣ�������Ҳ�Ѿ��޸Ľ����ˣ�FirstThunk����ȫ�����Ǻ����ĵ�ַ�ˣ�������ʲô�����Ӱ˵Ĺ����ˡ�*/

	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		DWORD Offset = (DWORD)PE - (DWORD)ImageBase;
		//���ƫ�����ǵ�ǰPE���ڴ��е�ƫ�Ƽ�ȥPE�ļ�Ӧ�����صĻ�ַ��

		IMAGE_BASE_RELOCATION *RelocationImage = (IMAGE_BASE_RELOCATION *)(PE + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		
		for (; RelocationImage->VirtualAddress != 0;)
		{
			/*�������Ϊʲôд
			#define CountRelocationEntries(dwBlockSize)		\
			(dwBlockSize -								\
			sizeof(BASE_RELOCATION_BLOCK)) /			\
			sizeof(BASE_RELOCATION_ENTRY)
			�Ͳ鿴���*/
			DWORD NumberOfBlocks = (RelocationImage->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

			unsigned short * Block = (unsigned short *)((char*)RelocationImage + sizeof(IMAGE_BASE_RELOCATION));
			for (int i = 0; i < NumberOfBlocks; ++i, Block++)
			{
				unsigned short addr = *Block & 0x0fff;											//�õ�12λ��Ϊ��־��
				unsigned short sign = *Block >> 12;												//����λ��Ϊ��־������
				if (sign == 3)
				{
					DWORD AddressOffset = RelocationImage->VirtualAddress + addr;				//Block�ǵ�ǰҳ���ڲ��ı��˵�ַ�����Լ��ϵ�ǰҳ���λ�ü�����ƫ�Ƶ�ַ��
					*(long *)(PE + AddressOffset) += Offset;									//��PE���ڴ����ҵ�Ҫ�ض�λ�ĵ�ַ��Ȼ��ѵ�ַ����ƫ��ɡ�������Ҫ��ǿ��ת����long���ͣ�����ռ���ĸ��ֽ�
				}
				else if (sign == 0)
				{
					//signΪ0��ģ�������Ϊ�˶����ڴ档
				}
			}
			RelocationImage = (IMAGE_BASE_RELOCATION *)((char*)RelocationImage + RelocationImage->SizeOfBlock);
		}
	}
	DWORD OldProtect;						//����������ǰ�ڴ������
	VirtualProtect(PE, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect);
	
	EntryPoint += (DWORD)PE;
	_asm call EntryPoint;

	delete[] FileContent;
	return true;
}

int main()
{
	char FileName[200];
	cout << "�������ļ����ƣ�";
	cin >> FileName;
	HANDLE hFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == NULL)
	{
		cout << GetLastError() << endl;
		return -1;
	}
	if (IsPEFile(hFile))
	{
		cout << "��PE�ļ���" << endl;
		int i;
		cout << "�Ƿ���з���(1������0������)��";
		while (TRUE)
		{
			cin >> i;
			if (1 == i)
			{
				if (AnalyPE())
				{
					while (TRUE)
					{
						cout << "�Ƿ����PE���أ�1���أ�0�����أ���";
						cin >> i;
						if (1 == i)
						{
							LoadPE();
							break;
						}
						else if(0 == i)
						{
							delete[]FileContent;
							break;
						}
						else
						{
							cout << "���������������룡";
							continue;
						}
					}
					break;
				}
			}
			else if (0 == i)
			{
				delete[]FileContent;
				break;
			}
			else
			{
				cout << "���������������룡";
				continue;
			}
		}
	}
	else
		cout << "����PE�ļ���" << endl;
	system("pause");
	return 0;
}