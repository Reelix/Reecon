using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
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
            Console.WriteLine(FindCommonFiles(url));
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
            Console.WriteLine(pageInfo);
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
            if (!url.EndsWith("/"))
            {
                url += "/";
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
                // Common images folder
                "images/",
                // Hidden mail server
                "mail/",
                // Admin stuff
                "admin.php",
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
                "phpmyadmin/"
            };
            string returnText = "";
            foreach (string file in commonFiles)
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url + file);
                // Ignore invalid SSL Cert
                request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                request.AllowAutoRedirect = false;
                request.Timeout = 5000;
                try
                {
                    using (var response = request.GetResponse() as HttpWebResponse)
                    {
                        if (response.StatusCode == HttpStatusCode.OK)
                        {
                            // Since it's readable - Let's deal with it!
                            try
                            {
                                returnText += $"- Common Path is readable: {url}{file}" + Environment.NewLine;
                                string pageText = new StreamReader(response.GetResponseStream()).ReadToEnd();
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
                                    catch
                                    { }
                                    returnText += "--- Download: https://raw.githubusercontent.com/arthaud/git-dumper/master/git-dumper.py" + Environment.NewLine;
                                    returnText += $"--- Run: python3 git-dumper.py {url}{file} .git" + Environment.NewLine;
                                    returnText += "--- Get the logs: git log --pretty=format:\"%h - %an (%ae): %s %b\"" + Environment.NewLine;
                                    returnText += "--- Show a specific commit: git show 2eb93ac (Press q to close)" + Environment.NewLine;
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
    }
}
