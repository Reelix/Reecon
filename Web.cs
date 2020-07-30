using System;
using System.Collections.Generic;
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
        }

        private static void ScanPage(string url)
        {
            string pageText;
            try
            {
                Console.WriteLine("Loading Page Data...");
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
            string emailInfo = FindEmails(pageText, doubleDash);
            string linkInfo = FindLinks(pageText, doubleDash);
            if (emailInfo != "")
            {
                return emailInfo + Environment.NewLine + linkInfo;
            }
            else
            {
                return linkInfo;
            }
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
            return returnInfo.Trim(Environment.NewLine.ToCharArray());
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
    }
}
