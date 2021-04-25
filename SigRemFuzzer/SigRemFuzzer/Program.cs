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


using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SigRemFuzzer
{
	class Program
	{
		static void Main(string[] args)
		{
			RemSigCountStats stats = new RemSigCountStats();

			EnumerateFolder(@"C:\", ref stats);
		}



		static void EnumerateFolder(string strFldrPath, ref RemSigCountStats stats)
		{
			if(!strFldrPath.EndsWith(@"\"))
				strFldrPath += @"\";

			string[] strFiles = null;
			try
			{
				strFiles = Directory.GetFiles(strFldrPath);
			}
			catch(UnauthorizedAccessException)
			{
				//Skip it
			}

			if (strFiles != null)
			{
				foreach (string strFile in strFiles)
				{
					Console.CursorTop = 0;
					Console.WriteLine(strFile + "\t\t\t\t\t\t\t\t\t");

					//Do the fuzzing of the file
					FuzzFile(strFile, ref stats);

					//Output stats
					Console.CursorTop = 10;
					Console.Write(
						$"Success:      {stats.nCount_Success}\n" +
						$"Not PE:       {stats.nCount_NotPE}\n" +
						$"Failed Open:  {stats.nCount_FailedToOpen}\n" +
						$"No signature: {stats.nCount_NoSig}\n"
						);
				}

				foreach (string strFldr in Directory.GetDirectories(strFldrPath))
				{
					EnumerateFolder(strFldr, ref stats);

				}
			}
		}


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

		class RemSigCountStats
		{
			public int nCount_Success { get; set; }
			public int nCount_NotPE { get; set; }
			public int nCount_FailedToOpen { get; set; }
			public int nCount_NoSig { get; set; }
		}

		static void FuzzFile(string strFilePath, ref RemSigCountStats stats)
		{
			try
			{
				Process proc = new Process();
				proc.StartInfo.FileName = @"..\..\..\..\Debug\SigRemover.exe";
				proc.StartInfo.Arguments = $"-i \"{ strFilePath }\"";
				proc.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;

				proc.Start();

				proc.WaitForExit();

				EXIT_CODES exitCode = (EXIT_CODES)proc.ExitCode;

				//Check exit codes
				if(exitCode == EXIT_CODES.XC_BinaryHasNoSignature)
				{
					stats.nCount_NoSig++;
				}
				else if(exitCode == EXIT_CODES.XC_FailedToOpen)
				{
					stats.nCount_FailedToOpen++;
				}
				else if(exitCode == EXIT_CODES.XC_Not_PE_File)
				{
					stats.nCount_NotPE++;
				}
				else if(exitCode == EXIT_CODES.XC_Success)
				{
					stats.nCount_Success++;
				}
				else
				{
					//This needs our attention!
					Console.WriteLine($"Failed exit code: { exitCode } in file: { strFilePath}");
				}
			}
			catch(Exception ex)
			{
				Console.WriteLine($"Exception: { ex.ToString() }");
			}
		}


	}
}
