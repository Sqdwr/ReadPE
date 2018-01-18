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
	/*因为上文已经确定了是PE文件，所以这里我懒得再确认一次了*/
	cout << hex;
	cout << "默认加载地址为：" << NtHeader->OptionalHeader.ImageBase << endl;
	cout << "内存页面大小为：" << NtHeader->OptionalHeader.SectionAlignment << endl;
	cout << "硬盘区块大小为：" << NtHeader->OptionalHeader.FileAlignment << endl;
	cout << "默认的堆栈大小是：" << NtHeader->OptionalHeader.SizeOfStackCommit << endl;
	cout << "默认的堆栈限制大小是：" << NtHeader->OptionalHeader.SizeOfStackCommit << endl;
	cout << "本文件有" << NtHeader->FileHeader.NumberOfSections << "个区块" << endl;
	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0)
		cout << "当前文件存在TLS表，请确认后再打开！（TLS表时长作为病毒/加壳代码的所在地）！" << endl;
	cout << "----------------------------------------------------------------" << endl;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(NtHeader);
	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++pSection)
	{
		cout << "第" << i + 1 << "个区块的名字是：" << pSection->Name << endl;
		cout << "本节区在内存中的起始地址是：" << pSection->VirtualAddress << endl;
		cout << "本节区在内存中的大小为：" << pSection->Misc.VirtualSize << endl;
		cout << "本节区在文件中的起始：" << pSection->PointerToRawData << endl;
		cout << "本节区在磁盘中的大小为：" << pSection->SizeOfRawData << endl;
	}
	cout << "----------------------------------------------------------------" << endl << endl;

	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
	{
		IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)(FileContent + TurnRvaIntoRaw(NtHeader, NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
		for (; ImportDescriptor->Name != NULL; ++ImportDescriptor)
		{
			cout << (char *)(FileContent + TurnRvaIntoRaw(NtHeader, ImportDescriptor->Name)) << "中导入函数为：" << endl;
			IMAGE_THUNK_DATA *ThunkData = (IMAGE_THUNK_DATA *)(FileContent + TurnRvaIntoRaw(NtHeader, ImportDescriptor->FirstThunk));
			for (; ThunkData->u1.Ordinal != 0; ThunkData++)
			{
				if (ThunkData->u1.Ordinal & 0x80000000)				//如果首位为1则是为序号输入，否则是姓名输入
					cout << "函数序号为：" << (ThunkData->u1.Ordinal & 0x0000ffff) << endl;
				else
				{
					IMAGE_IMPORT_BY_NAME *ImportName = (IMAGE_IMPORT_BY_NAME *)(FileContent + TurnRvaIntoRaw(NtHeader,ThunkData->u1.AddressOfData));
					cout << "函数名称为：" << ImportName->Name << endl;
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
	
	DWORD ImageSize = NtHeader->OptionalHeader.SizeOfImage;							//程序在内存中的大小。
	char *PE = new char[ImageSize];
	
	DWORD HeaderSize = NtHeader->OptionalHeader.SizeOfHeaders;						//所有HEADERS的大小。
	memcpy(PE, FileContent, HeaderSize);

	DWORD EntryPoint = NtHeader->OptionalHeader.AddressOfEntryPoint;				//程序的入口地址的RVA。

	DWORD ImageBase = NtHeader->OptionalHeader.ImageBase;							//程序加载的基址

	IMAGE_SECTION_HEADER * SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
		memcpy(PE + SectionHeader->VirtualAddress, FileContent + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);

	/*至此复制好了所有的东西，下面需要把导入表替换了*/

	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
	{
		IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)(PE + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		for (; ImportDescriptor->Name != NULL; ++ImportDescriptor)
		{
			HMODULE hModule = LoadLibraryA((char *)(PE + ImportDescriptor->Name));

			if (hModule == NULL)
			{
				cout << "LoadLibrary失败！" << endl;
				return false;
			}

			IMAGE_THUNK_DATA *ThunkData = (IMAGE_THUNK_DATA *)(PE + ImportDescriptor->FirstThunk);
			for (; ThunkData->u1.Ordinal != 0; ThunkData++)
			{
				if (ThunkData->u1.Ordinal & 0x80000000)				//如果首位为1则是为序号输入，否则是姓名输入
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

	/*好了，如今导入表也已经修改结束了，FirstThunk里面全部都是函数的地址了，不再是什么杂七杂八的鬼东西了。*/

	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		DWORD Offset = (DWORD)PE - (DWORD)ImageBase;
		//这个偏移量是当前PE在内存中的偏移减去PE文件应当加载的基址。

		IMAGE_BASE_RELOCATION *RelocationImage = (IMAGE_BASE_RELOCATION *)(PE + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		
		for (; RelocationImage->VirtualAddress != 0;)
		{
			/*这里具体为什么还是要看我的补充。。不打算写在这了。*/
			DWORD NumberOfBlocks = (RelocationImage->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

			unsigned short * Block = (unsigned short *)((char*)RelocationImage + sizeof(IMAGE_BASE_RELOCATION));
			for (int i = 0; i < NumberOfBlocks; ++i, Block++)
			{
				unsigned short addr = *Block & 0x0fff;											//用低12位作为标志。
				unsigned short sign = *Block >> 12;												//高四位作为标志来运算
				if (sign == 3)
				{
					DWORD AddressOffset = RelocationImage->VirtualAddress + addr;				//Block是当前页面内部的便宜地址，所以加上当前页面的位置即是总偏移地址。
					*(long *)(PE + AddressOffset) += Offset;									//在PE的内存中找到要重定位的地址，然后把地址加上偏差即可。这里需要先强制转化成long类型，让他占用四个字节
				}
				else if (sign == 0)
				{
					//sign为0的模块仅仅是为了对齐内存。
				}
			}
			RelocationImage = (IMAGE_BASE_RELOCATION *)((char*)RelocationImage + RelocationImage->SizeOfBlock);
		}
	}
	DWORD OldProtect;						//用来保存以前内存的属性
	VirtualProtect(PE, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect);
	
	EntryPoint += (DWORD)PE;
	_asm call EntryPoint;

	delete[] FileContent;
	return true;
}

int main()
{
	char FileName[200];
	cout << "请输入文件名称：";
	cin >> FileName;
	HANDLE hFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == NULL)
	{
		cout << GetLastError() << endl;
		return -1;
	}
	if (IsPEFile(hFile))
	{
		cout << "是PE文件！" << endl;
		int i;
		cout << "是否进行分析(1分析，0不进行)：";
		while (TRUE)
		{
			cin >> i;
			if (1 == i)
			{
				if (AnalyPE())
				{
					while (TRUE)
					{
						cout << "是否进行PE加载（1加载，0不加载）：";
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
							cout << "输入错误，请继续输入！";
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
				cout << "输入错误，请继续输入！";
				continue;
			}
		}
	}
	else
		cout << "不是PE文件！" << endl;
	system("pause");
	return 0;
}