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


//Custom types
#pragma once


#define APP_NAME L"Binary File Digital Signature Remover App"
#define APP_VERSION L"1.0.2"


//#define FUZZING_BUILD			//Uncomment to generate a fuzzing build


enum EXIT_CODES {
	XC_Success = 0,
	XC_BinaryHasNoSignature = 1,

	XC_GEN_FAILURE = -1,
	XC_FailedToOpen = -2,
	XC_Not_PE_File = -3,
	XC_BadSignature = -4,
	XC_FailedChecksum = -5,
	XC_FailedFileWrite = -6,
};




#define CHECK_PTR_4_OVERRUN(p_s, end) 	((BYTE*)(p_s) >= (end) || (BYTE*)(p_s) + sizeof(*(p_s)) >= (end))

#define SIZEOF_TEXT(t) (_countof(t) - 1)




