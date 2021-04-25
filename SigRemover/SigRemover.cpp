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


// SigRemover.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "CSigRem.h"




int _tmain(int argc, WCHAR* argv[])
{
	//RETURN:
	//		= See values in EXIT_CODES enum
	int nExitCode = (int)XC_GEN_FAILURE;

#ifdef FUZZING_BUILD
	wprintf(L"*** FUZZING BUILD ***\n");
#endif

	//Do we have a command line?
	if (argc > 1)
	{
		LPCTSTR pInputFile = NULL;
		LPCTSTR pOutputFile = NULL;

		//Go through command line parameters
		for (int p = 1; p < argc; p++)
		{
			LPCTSTR pCmdParam = argv[p];

			//Check if we need it
			if (CSigRem::IsCmdLineParam(pCmdParam, L"i"))
			{
				//Must have the following file path
				if (p + 1 < argc)
				{
					//Remember it
					pInputFile = argv[++p];
				}
				else
				{
					//Error
					CSigRem::ReportOSError(22, L"-i command line parameter requires a file path");
					break;
				}
			}
			else if (CSigRem::IsCmdLineParam(pCmdParam, L"o"))
			{
				//Must have the following file path
				if (p + 1 < argc)
				{
					//Remember it
					pOutputFile = argv[++p];
				}
				else
				{
					//Error
					CSigRem::ReportOSError(22, L"-o command line parameter requires a file path");
					break;
				}
			}
			else if (CSigRem::IsCmdLineParam(pCmdParam, L"?") ||
				CSigRem::IsCmdLineParam(pCmdParam, L"h"))
			{
				//Show help
				CSigRem::ShowHelpInfo();

				pInputFile = NULL;
				pOutputFile = NULL;

				nExitCode = 0;
				break;
			}
			else
			{
				//Unsupported parameter
				CSigRem::ReportOSError(22, L"Unsupported command line parameter \"%s\", use -? for more info", pCmdParam);

				pInputFile = NULL;
				pOutputFile = NULL;

				break;
			}
		}


		//See if we have an input file to work with?
		if (pInputFile)
		{
			//Remove binary signature from the file
			nExitCode = (int)CSigRem::RemoveDigitalSignature(pInputFile, pOutputFile);
		}
		else
		{
			//Do we have just an output?
			if (pOutputFile)
			{
				//Error
				CSigRem::ReportOSError(22, L"-o command line parameter requires the -i parameter");
			}
		}
	}
	else
	{
		//No command line
		WCHAR buffYr[32];
		SYSTEMTIME st = {};
		::GetLocalTime(&st);
		const int knStartYear = 2021;
		if (st.wYear <= knStartYear)
		{
			verify(SUCCEEDED(::StringCchPrintf(buffYr, _countof(buffYr), L"%04u", knStartYear)));
		}
		else
		{
			verify(SUCCEEDED(::StringCchPrintf(buffYr, _countof(buffYr), L"%04u-%04u", knStartYear, st.wYear)));
		}

		wprintf(
			L"%s\n"
			L"v.%s\n"
			L"Copyright (C) %s by www.dennisbabkin.com\n"
			L"\n"
			L"Use -h command line switch for more info...\n"
			,
			APP_NAME,
			APP_VERSION,
			buffYr);

		nExitCode = 0;
	}

	return nExitCode;
}


