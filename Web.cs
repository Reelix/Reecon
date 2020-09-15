using Pastel;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
            string pageText;
            try
            {
                Console.WriteLine("Scanning...");
                pageText = wc.DownloadString(url);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return;
            }
            string pageInfo = FindInfo(pageText);
            if (pageInfo.Trim() != "")
            {
                Console.WriteLine(pageInfo);
            }
        }

        public static string FindInfo(string pageText, bool doubleDash = false)
        {
            string foundInfo = "";
            if (pageText.Contains("/wp-content/themes/") && pageText.Contains("/wp-includes/"))
            {
                foundInfo += "- Wordpress detected! Run wpscan!" + Environment.NewLine;
                foundInfo += "-- hydra -L users.txt -P passwords.txt site.com http-post-form \"/blog/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location\" -I -t 50" + Environment.NewLine;
            }
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
            // WebClient throws an error on 403 (Forbidden) and 404 (Not Found) pages           
            int notFoundLength = -1;
            try
            {
                WebClient wc = new WebClient();
                string wildcardURL = url + "be0df04b-f5ff-4b4f-af99-00968cf08fed";
                string test = wc.DownloadString(wildcardURL);
                notFoundLength = test.Length;
                returnText += $"- Wildcard paths such as {wildcardURL} return - This may cause issues..." + Environment.NewLine;
            }
            catch { }

            bool skipPHP = false;
            // PHP wildcards can be differnt
            try
            {
                WebClient wc = new WebClient();
                string test = wc.DownloadString(url + "be0df04b-f5ff-4b4f-af99-00968cf08fed.php");
                notFoundLength = test.Length;
                returnText += "- .php wildcard paths returns - Skipping PHP" + Environment.NewLine;
                skipPHP = true;
            }
            catch { }

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
                // Common images folder
                "images/",
                // Hidden mail server
                "mail/",
                // Admin stuff
                "admin.php",
                "admin/",
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
                "bolt-public/img/bolt-logo.png"
            };

            if (skipPHP)
            {
                commonFiles.RemoveAll(x => x.EndsWith(".php"));
            }
            foreach (string file in commonFiles)
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url + file);
                request.Method = "HEAD";
                // Ignore invalid SSL Cert
                request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                request.AllowAutoRedirect = false;
                request.Timeout = 5000;
                try
                {
                    using (var response = request.GetResponse() as HttpWebResponse)
                    {
                        var headers = response.Headers;
                        if (response.StatusCode == HttpStatusCode.OK)
                        {
                            // Since it's readable - Let's deal with it!
                            try
                            {
                                string pageText = new StreamReader(response.GetResponseStream()).ReadToEnd();
                                if (pageText.Length != notFoundLength)
                                {
                                    returnText += "- " + $"Common Path is readable: {url}{file}".Pastel(Color.Orange) + Environment.NewLine;
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
                                                returnText += "--- Show a specific commit: git show 2eb93ac (Press q to close)" + Environment.NewLine;
                                                continue;
                                            }
                                        }
                                        catch { }
                                        returnText += "--- Download: https://raw.githubusercontent.com/arthaud/git-dumper/master/git-dumper.py" + Environment.NewLine;
                                        returnText += $"--- Run: python3 git-dumper.py {url}{file} .git" + Environment.NewLine;
                                        returnText += "--- Get the logs: git log --pretty=format:\"%h - %an (%ae): %s %b\"" + Environment.NewLine;
                                        returnText += "--- Show a specific commit: git show 2eb93ac (Press q to close)" + Environment.NewLine;
                                    }
                                    // Bolt
                                    else if (file == "bolt-public/img/bolt-logo.png")
                                    {
                                        returnText += "-- Bolt CMS!" + Environment.NewLine;
                                        returnText += $"-- Admin Page: {url}bolt" + Environment.NewLine;
                                        returnText += "-- If you get details and the version is 3.6.* or 3.7: https://www.rapid7.com/db/modules/exploit/unix/webapp/bolt_authenticated_rce" + Environment.NewLine;
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
                        else if (response.StatusCode == HttpStatusCode.Forbidden)
                        {
                            // Forbidden is still useful
                            returnText += $"- Common Path is Forbidden: {url}{file}" + Environment.NewLine;
                        }
                        else if (response.StatusCode == HttpStatusCode.Redirect)
                        {
                            returnText += $"- Common Path redirects: {url}{file}" + Environment.NewLine;
                            if (headers != null && headers.Get("Location") != null)
                            {
                                returnText += $"-- Redirection Location: {headers.Get("Location")}" + Environment.NewLine;
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Unknown response for {file} - {response.StatusCode}");
                        }
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
                            Console.WriteLine("FindCommonFiles - Something weird happened: " + ex.Message);
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

        public static (HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, WebHeaderCollection Headers, X509Certificate2 SSLCert) GetHTTPInfo(string url)
        {
            string pageTitle = "";
            string pageText = "";
            string dns = "";
            HttpStatusCode statusCode = new HttpStatusCode();
            WebHeaderCollection headers = null;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            try
            {
                // Ignore invalid SSL Cert
                request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
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
            catch (WebException ex)
            {
                if (ex.Response == null)
                {
                    if (ex.Message != null)
                    {
                        if (ex.Message.Trim() == "The request was aborted: Could not create SSL/TLS secure channel.")
                        {
                            Console.WriteLine("GetHTTPInfo.Error.SSLTLS - Bug Reelix to fix this");
                        }
                        else if (ex.Message.Trim() == "The underlying connection was closed: An unexpected error occurred on a send.")
                        {
                            // Ignore it
                        }
                        else if (ex.Message.Trim() == "The operation has timed out.")
                        {
                            // Ignore it
                        }
                        else if (ex.Message.Trim() == "Error: SecureChannelFailure (Authentication failed, see inner exception.)")
                        {
                            // Ignore it - Should we?
                        }
                        else if (ex.Message.Trim() == "Error: ConnectFailure (Connection refused)" || ex.Message.Trim() == "Error: ConnectFailure (No route to host)")
                        {
                            // The port is probably closed to us
                            // Ignore it - It's handled elswhere
                        }
                        else
                        {
                            Console.WriteLine("GetHTTPInfo.Error: " + ex.Message);
                        }
                    }
                    return (statusCode, null, null, null, null, null);
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
                return (statusCode, null, null, null, null, null);
            }

            if (pageText.Contains("<title>") && pageText.Contains("</title>"))
            {
                pageTitle = pageText.Remove(0, pageText.IndexOf("<title>") + "<title>".Length);
                pageTitle = pageTitle.Substring(0, pageTitle.IndexOf("</title>"));
            }
            X509Certificate2 cert = null;
            if (request.ServicePoint.Certificate != null)
            {
                cert = new X509Certificate2(request.ServicePoint.Certificate);
            }
            return (statusCode, pageTitle, pageText, dns, headers, cert);
        }

        public static string FormatHTTPInfo(HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, WebHeaderCollection Headers, X509Certificate2 SSLCert)
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
                responseText += "- Page Title: " + PageTitle.Trim() + Environment.NewLine;
            }
            if (PageText.Length > 0)
            {
                if (PageText.Length < 250)
                {
                    responseText += "- Page Text: " + PageText.Trim() + Environment.NewLine;
                }
                if (PageText.Contains("/wp-content/themes/") && PageText.Contains("/wp-includes/"))
                {
                    responseText += "- Wordpress detected! Run wpscan!" + Environment.NewLine;
                    responseText += "-- hydra -L users.txt -P passwords.txt site.com http-post-form \"/blog/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location\" -I -t 50" + Environment.NewLine;
                }
            }
            if (!string.IsNullOrEmpty(DNS))
            {
                responseText += "- DNS: " + DNS + Environment.NewLine;
            }
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
                        responseText += "-- Webmin Server Detected" + Environment.NewLine;
                        // 1.890, 1.900-1.920 - http://www.webmin.com/changes.html
                        if (serverText.StartsWith("MiniServ/1.890") || serverText.StartsWith("MiniServ/1.900") || serverText.StartsWith("MiniServ/1.910") || serverText.StartsWith("MiniServ/1.920"))
                        {
                            responseText += "--- Possible Vulnerable Version: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/webmin_backdoor.rb" + Environment.NewLine;
                        }
                    }
                }
                // Useful info
                if (headerList.Contains("X-Powered-By"))
                {
                    headerList.Remove("X-Powered-By");
                    responseText += "- X-Powered-By: " + Headers.Get("X-Powered-By") + Environment.NewLine;
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
                    if (contentType != "text/html")
                    {
                        // A unique content type - Might be interesting
                        responseText += "- Content-Type: " + Headers.Get("Content-Type") + Environment.NewLine;
                    }
                }
                responseText += "- Other Headers: " + string.Join(",", headerList) + Environment.NewLine;
            }
            if (SSLCert != null)
            {
                string certIssuer = SSLCert.Issuer;
                string certSubject = SSLCert.Subject;
                // string certAltName = SSLCert.SubjectName.Name;
                responseText += "- SSL Cert Issuer: " + certIssuer + Environment.NewLine;
                responseText += "- SSL Cert Subject: " + certSubject + Environment.NewLine;
                if (SSLCert.Extensions != null)
                {
                    X509ExtensionCollection extensionCollection = SSLCert.Extensions;
                    foreach (X509Extension extension in extensionCollection)
                    {
                        string extensionType = extension.Oid.FriendlyName;
                        if (extensionType == "Subject Alternative Name")
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
    }
}
