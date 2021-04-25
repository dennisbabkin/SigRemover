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


//SigRemover main functionality
#pragma once

#include <tchar.h>
#include <Windows.h>
#include <strsafe.h>
#include <assert.h>
#include <new>

#include <imagehlp.h>
#pragma comment(lib, "Imagehlp.lib")

#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")


#include "Types.h"



#ifdef _DEBUG
#define verify(f) assert(f)
#else
#define verify(f) (f)
#endif

#define SUFFIX_FILE_NAME L" (NoSig)"


class CSigRem
{
public:
	static EXIT_CODES RemoveDigitalSignature(LPCTSTR pStrFilePath, LPCTSTR pStrOutputFile = NULL);
	static BOOL IsCmdLineParam(LPCTSTR pCmd, LPCTSTR pToCheck);
	static void ReportOSError(int nOSError = ::GetLastError(), LPCTSTR pStrFmt = NULL, ...);
	static void ShowHelpInfo();
protected:
	static const WCHAR* getFormattedErrorMsg(int nOSError, WCHAR* pBuffer, size_t szchBuffer);
	static EXIT_CODES process_PE_File(BYTE* pBaseAddr, ULONG szcbMem, ULONG& uicbNewFileSz, int& nOSErr);
};

