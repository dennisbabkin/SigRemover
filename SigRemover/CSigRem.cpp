//  
//    Binary File Digital Signature Remover App
//    "Utility to remove digital code signature from binary PE files in Windows."
//    Copyright (c) 2021 www.dennisbabkin.com
//    
//        https://dennisbabkin.com/sigremover
//
//        https://dennisbabkin.com/blog/?i=AAA10400
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//    
//        https://www.apache.org/licenses/LICENSE-2.0
//    
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//  
//


#include "CSigRem.h"




EXIT_CODES CSigRem::RemoveDigitalSignature(LPCTSTR pStrFilePath, LPCTSTR pStrOutputFile)
{
	//'pStrFilePath' = input path for PE file to remove signature from
	//'pStrOutputFile' = if not NULL, and not L"", file path to save resulting PE file (or use file suffix on existing file)
	EXIT_CODES nResult = XC_FailedToOpen;

	//Open file for reading
	HANDLE hFile = ::CreateFile(pStrFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER liFileSz = {};
		if (::GetFileSizeEx(hFile, &liFileSz))
		{
			//Make sure the file is not too large
			if ((ULONGLONG)liFileSz.QuadPart < INT_MAX)
			{
				//Reserve memory for the file data
				ULONG dwcbFileSz = (ULONG)liFileSz.QuadPart;
				BYTE* pFileMem = new (std::nothrow) BYTE[dwcbFileSz];
				if (pFileMem)
				{
					//Read data into memory
					DWORD dwcbRead = -1;
					if (::ReadFile(hFile, pFileMem, dwcbFileSz, &dwcbRead, NULL))
					{
						if (dwcbRead == dwcbFileSz)
						{
							int nOSErr = -1;
							ULONG uicbNewFileSz = 0;
							nResult = process_PE_File(pFileMem, dwcbRead, uicbNewFileSz, nOSErr);

							switch (nResult)
							{
							case XC_Success:
							{
								//All good - need to save new file with data from 'pFileMem' of size 'uicbNewFileSz' bytes
								assert((int)uicbNewFileSz > 0);

#ifndef FUZZING_BUILD
								//Assume failure
								nResult = XC_FailedFileWrite;

								WCHAR* pNewFileName = NULL;


								//Do we need to make an output file
								if (!pStrOutputFile ||
									!pStrOutputFile[0])
								{
									//Need to generate output file name
									pStrOutputFile = NULL;

									//Set new file name
									size_t szchLnFileName = wcslen(pStrFilePath);
									size_t szchLnNewFileName = szchLnFileName + 1 + SIZEOF_TEXT(SUFFIX_FILE_NAME);		//Account for terminating null
									pNewFileName = new (std::nothrow) WCHAR[szchLnNewFileName];
									if (pNewFileName)
									{
										//Find extension
										LPCTSTR pStrExt = ::PathFindExtension(pStrFilePath);
										intptr_t nExtOffset = pStrExt - pStrFilePath;
										assert(nExtOffset >= 0);

										//Make new file name
										HRESULT hr = ::StringCchPrintf(pNewFileName, szchLnNewFileName,
											L"%.*s%s%s"
											,
											nExtOffset, pStrFilePath,
											SUFFIX_FILE_NAME,
											pStrFilePath + nExtOffset
										);
										if (SUCCEEDED(hr))
										{
											//Use it
											pStrOutputFile = pNewFileName;
										}
										else
										{
											//Error
											assert(false);
											ReportOSError((int)hr, L"Failed to make new file name for: \"%s\"", pStrFilePath);
										}

									}
									else
									{
										//Error
										assert(false);
										ReportOSError(ERROR_OUTOFMEMORY, L"Failed to reserve memory for new file name");
									}
								}


								//Only if we have an output file
								if (pStrOutputFile)
								{
									//Create new file
									HANDLE hFile2 = ::CreateFile(pStrOutputFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
									if (hFile2 != INVALID_HANDLE_VALUE)
									{
										//Write into file
										DWORD dwcbWrtn = 0;
										if (::WriteFile(hFile2, pFileMem, uicbNewFileSz, &dwcbWrtn, NULL))
										{
											//Make sure all data has been written
											if (dwcbWrtn == uicbNewFileSz)
											{
												//We are all done
												nResult = XC_Success;

												wprintf(L"SUCCESS creating new binary file without signature:\n\"%s\"\n", pStrOutputFile);
											}
											else
											{
												//Error
												ReportOSError(4635, L"Failed to write all data to destination file: %s", pStrOutputFile);
											}
										}
										else
										{
											//Error
											ReportOSError(::GetLastError(), L"Failed to write to destination file: %s", pStrOutputFile);
										}

										//Close file
										verify(::CloseHandle(hFile2));


#ifdef _DEBUG
										if (nResult == XC_Success)
										{
											//Check that checksum was calculated correctly
											DWORD dwCheckSum1, dwCheckSum2;
											DWORD dwResChecksum = MapFileAndCheckSum(pStrOutputFile, &dwCheckSum1, &dwCheckSum2);
											assert(dwResChecksum == CHECKSUM_SUCCESS);
											assert(dwCheckSum1 == dwCheckSum2);
										}
#endif
									}
									else
									{
										//Error
										ReportOSError(::GetLastError(), L"Failed to create destination file: %s", pStrOutputFile);
									}
								}


								//Free mem
								if (pNewFileName)
								{
									//Free mem
									delete[] pNewFileName;
									pNewFileName = NULL;
								}
#endif

							}
							break;

							case XC_BinaryHasNoSignature:
								wprintf(L"Binary file has no digital signature: %s\n", pStrFilePath);
								break;

							case XC_BadSignature:
								ReportOSError(nOSErr, L"Specified file has incompatible digital signature: %s", pStrFilePath);
								break;

							case XC_FailedChecksum:
								ReportOSError(nOSErr, L"Failed to compute a checksum on the new file: %s", pStrFilePath);
								break;

							case XC_Not_PE_File:
								ReportOSError(nOSErr, L"Specified file is not a valid PE binary: %s", pStrFilePath);
								break;

							default:
								assert(nResult == XC_FailedToOpen);
								ReportOSError(nOSErr, L"Failed to process specified binary file: %s", pStrFilePath);
								break;
							}
						}
						else
							ReportOSError(707, L"Didn't read all file data: %s", pStrFilePath);
					}
					else
						ReportOSError(::GetLastError(), L"Failed to read data from file: %s", pStrFilePath);

					//Free mem
					delete[] pFileMem;
					pFileMem = NULL;
				}
				else
					ReportOSError(ERROR_OUTOFMEMORY, L"Failed to reserve memory to read file: %s", pStrFilePath);
			}
			else
				ReportOSError(8312, L"File is too large: %s", pStrFilePath);
		}
		else
			ReportOSError(::GetLastError(), L"Failed to get file size: %s", pStrFilePath);

		//Close handle
		verify(::CloseHandle(hFile));
	}
	else
	{
		//Error
		ReportOSError(::GetLastError(), L"Failed to open binary file: %s", pStrFilePath);
	}

	return nResult;
}


void CSigRem::ReportOSError(int nOSError, LPCTSTR pStrFmt, ...)
{
	//Pick the right format for the error code
	WCHAR buffErrCode[32];
	buffErrCode[0] = 0;
	if ((UINT)nOSError & 0xC0000000)
	{
		//Hex
		verify(SUCCEEDED(::StringCchPrintf(buffErrCode, _countof(buffErrCode), L"0x%X", nOSError)));
	}
	else
	{
		//Unsigned int
		verify(SUCCEEDED(::StringCchPrintf(buffErrCode, _countof(buffErrCode), L"%u", nOSError)));
	}

	buffErrCode[_countof(buffErrCode) - 1] = 0;

	//Format error message
	WCHAR buffError[1024];
	buffError[0] = 0;
	getFormattedErrorMsg(nOSError, buffError, _countof(buffError));

	//Do we have a user message?
	if (pStrFmt &&
		pStrFmt[0])
	{
		//We have a user message
		va_list argList;
		va_start(argList, pStrFmt);

		//Get length
		int nLnBuff = _vscwprintf(pStrFmt, argList);

		//Reserve a buffer
		WCHAR* pBuff = new (std::nothrow) WCHAR[nLnBuff + 1];
		if (pBuff)
		{
			//Do formatting
			vswprintf_s(pBuff, nLnBuff + 1, pStrFmt, argList);
			pBuff[nLnBuff] = 0;

			wprintf(L"%s\n"
				L"ERROR: (%s) %s\n"
				, 
				pBuff, 
				buffErrCode, 
				buffError);

			//Free mem
			delete[] pBuff;
			pBuff = NULL;
		}
		else
			assert(false);

		va_end(argList);
	}
	else
	{
		//No user message
		wprintf(L"ERROR: (%s) %s\n", buffErrCode, buffError);
	}

	//Restore last error
	::SetLastError(nOSError);
}


const WCHAR* CSigRem::getFormattedErrorMsg(int nOSError, WCHAR* pBuffer, size_t szchBuffer)
{
	//'pBuffer' = buffer to fill in with error description
	//'szchBuffer' = size of 'pBuffer' in WCHARs
	//RETURN:
	//		= Pointer to 'pBuffer' (always NULL-terminated)
	int nPrev_OSError = ::GetLastError();

	if (szchBuffer)
	{
		if (nOSError)
		{
			LPVOID lpMsgBuf = NULL;
			DWORD dwRes;

			pBuffer[0] = 0;

			dwRes = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				nOSError,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&lpMsgBuf, 0, NULL);

			if (lpMsgBuf)
			{
				verify(SUCCEEDED(::StringCchCopy(pBuffer, szchBuffer, (LPCTSTR)lpMsgBuf)));
				::LocalFree(lpMsgBuf);
				lpMsgBuf = NULL;
			}

			//Safety null
			pBuffer[szchBuffer - 1] = 0;

			//Remove all \n and \r chars
			for (WCHAR* pS = pBuffer; ; pS++)
			{
				WCHAR z = *pS;
				if (!z)
					break;

				if (z == L'\n' || z == L'\r')
					*pS = L' ';
			}
		}
		else
		{
			//No errors
			pBuffer[0] = 0;
		}
	}
	else
		assert(false);

	::SetLastError(nPrev_OSError);
	return pBuffer;
}


EXIT_CODES CSigRem::process_PE_File(BYTE* pBaseAddr, ULONG szcbMem, ULONG& uicbNewFileSz, int& nOSErr)
{
	//'pBaseAddr' = pointer to the beginning of the PE file (it should not be mapped!)
	//'szcbMem' = size of 'pBaseAddr' in BYTEs
	//'uicbNewFileSz' = receives new file size in BYTEs after signature has been removed (valid only if result is XC_Success)
	//'nOSErr' = receives OS error code, if any
	BYTE* pEndAddr = pBaseAddr + szcbMem;

	if ((LONG)szcbMem < sizeof(IMAGE_DOS_HEADER))
	{
		//Error
		nOSErr = ERROR_BAD_EXE_FORMAT;
		return XC_Not_PE_File;
	}

	//Define DOS header
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	size_t szcbNtHdr = (ULONG)pDosHdr->e_lfanew + sizeof(IMAGE_NT_HEADERS64);		//Assume the worst case (or 64-bit)

	if (szcbNtHdr > szcbMem)
	{
		//Error
		nOSErr = ERROR_BAD_EXE_FORMAT;
		return XC_Not_PE_File;
	}

	//Define NT headers
	IMAGE_NT_HEADERS* pNtHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + (ULONG)pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
#ifndef FUZZING_BUILD
		//Error
		nOSErr = ERROR_BAD_EXE_FORMAT;
		return XC_Not_PE_File;
#endif
	}

	//Get to sections
	IMAGE_SECTION_HEADER* pSections = (IMAGE_SECTION_HEADER*)(IMAGE_FIRST_SECTION(pNtHdr));
	if (CHECK_PTR_4_OVERRUN(pSections, pEndAddr))
	{
		//Error
		nOSErr = ERROR_BAD_EXE_FORMAT;
		return XC_Not_PE_File;
	}


	//Determine bitness and get some other info from the headers
	IMAGE_NT_HEADERS32* pNtHdr32 = NULL;
	IMAGE_NT_HEADERS64* pNtHdr64 = NULL;
	IMAGE_DATA_DIRECTORY* pDataDirectories = NULL;
	DWORD* pdwChecksum = NULL;

	switch (pNtHdr->OptionalHeader.Magic)
	{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		{
			//32-bit
			pNtHdr32 = (IMAGE_NT_HEADERS32*)pNtHdr;
			IMAGE_OPTIONAL_HEADER32* pIOH32 = &pNtHdr32->OptionalHeader;
			if (CHECK_PTR_4_OVERRUN(pIOH32, pEndAddr))
			{
				//Error
				nOSErr = ERROR_BAD_EXE_FORMAT;
				return XC_Not_PE_File;
			}

			pDataDirectories = pIOH32->DataDirectory;
			pdwChecksum = &pIOH32->CheckSum;
		}
		break;

		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		{
			//64-bit
			pNtHdr64 = (IMAGE_NT_HEADERS64*)pNtHdr;
			IMAGE_OPTIONAL_HEADER64* pIOH64 = &pNtHdr64->OptionalHeader;
			if (CHECK_PTR_4_OVERRUN(pIOH64, pEndAddr))
			{
				//Error
				nOSErr = ERROR_BAD_EXE_FORMAT;
				return XC_Not_PE_File;
			}

			pDataDirectories = pIOH64->DataDirectory;
			pdwChecksum = &pIOH64->CheckSum;
		}
		break;

		default:
		{
			//Error
			nOSErr = ERROR_BAD_EXE_FORMAT;
			return XC_Not_PE_File;
		}
	}


	assert(pDataDirectories);
	assert(pdwChecksum);


	//We need to examine IMAGE_DIRECTORY_ENTRY_SECURITY
	IMAGE_DATA_DIRECTORY* pID = &pDataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY];
	if (CHECK_PTR_4_OVERRUN(pID, pEndAddr))
	{
		//Error
		nOSErr = ERROR_BAD_EXE_FORMAT;
		return XC_Not_PE_File;
	}


	//See if we have any signature?
	if (!pID->Size &&
		!pID->VirtualAddress)
	{
		//No signature
		return XC_BinaryHasNoSignature;
	}


	//We will assume that the signature is always at the end of the binary file
	if (pID->VirtualAddress + pID->Size != szcbMem)
	{
		//Signature is not at the end of file
		nOSErr = 1466;
		return XC_BadSignature;
	}



	//Now start modifying the binary
	////////////////////////////////////////////////

	//Set new file size
	uicbNewFileSz = pID->VirtualAddress;

	//Remove digital signature from the PE header directory
	pID->Size = 0;
	pID->VirtualAddress = 0;

	//Update file checksum
	DWORD dwOrigCheckSum = 0, dwNewCheckSum = 0;
	PIMAGE_NT_HEADERS pIH = CheckSumMappedFile(pBaseAddr, uicbNewFileSz, &dwOrigCheckSum, &dwNewCheckSum);
	if (!pIH)
	{
		//Failed to compute new checksum
		nOSErr = ::GetLastError();
		return XC_FailedChecksum;
	}

	//Set new checksum in memory
	assert(pdwChecksum);
	*pdwChecksum = dwNewCheckSum;

	return XC_Success;
}


BOOL CSigRem::IsCmdLineParam(LPCTSTR pCmd, LPCTSTR pToCheck)
{
	//RETURN:
	//		= TRUE if 'pToCheck' is 'pCmd' command line parameter (case insensitive)

	if (pCmd &&
		pCmd[0] &&
		pToCheck &&
		pToCheck[0])
	{
		//Command must start with a letter only
		assert((pToCheck[0] >= 'a' && pToCheck[0] <= 'z') || (pToCheck[0] >= 'A' && pToCheck[0] <= 'Z') || pToCheck[0] == '?');

		WCHAR z = pCmd[0];
		if (z == '-' ||
			z == '/' ||
			z == '\\')
		{
			return ::CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, pCmd + 1, -1, pToCheck, -1) == CSTR_EQUAL;
		}
	}

	return FALSE;
}


void CSigRem::ShowHelpInfo()
{
	//Show help info to the console

	//Get current exe file name (without extension)
	WCHAR buffThis[MAX_PATH] = {};
	::GetModuleFileName(NULL, buffThis, _countof(buffThis));
	*::PathFindExtension(buffThis) = 0;
	LPCTSTR pThisFile = ::PathFindFileName(buffThis);

	wprintf(
		L"%s -i <File> [-o <File>]\n"
		L"\n"
		L"where:\n"
		L" -i  = specifies PE file to remove signature from:\n"
		L"        <File> = File path to read PE binary.\n"
		L" -o  = [optional] specifies destination PE file:\n"
		L"        If omitted, the new file name will have%s suffix in the same folder.\n"
		L"        <File> = File path to create new PE binary.\n"
		L"\n"
		L"Examples:\n"
		L" %s -i \"path-to\\file.exe\"\n"
		L" %s -i \"path-to\\file.exe\" -o \"path-to\\result.exe\"\n"
		L"\n"
		,
		pThisFile,
		SUFFIX_FILE_NAME,
		pThisFile,
		pThisFile
	);
}