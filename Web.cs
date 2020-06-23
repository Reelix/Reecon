using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using System.Linq;

namespace Reecon
{
    class Web
    {
        static WebClient wc = new WebClient();

        public static void GetInfo(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Web Usage: reecon -web http://site.com/");
                return;
            }
            string url = args[1];
            ScanPage(url);

        }
        public static void ScanPage(string url)
        {
            string pageText = wc.DownloadString(url);
            FindEmails(pageText);
            FindLinks(pageText);
        }

        public static void FindEmails(string text)
        {
            // Do not change this Regex
            Regex emailRegex = new Regex(@"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", RegexOptions.IgnoreCase);
            MatchCollection emailMatches = emailRegex.Matches(text);
            List<string> matchList = General.MatchCollectionToList(emailMatches);
            foreach (string match in matchList)
            {
                Console.WriteLine("- " + match);
            }
        }

        public static void FindLinks(string text)
        {
            Regex linkRegex = new Regex(@"((http|ftp|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&amp;:/~\+#]*[\w\-\@?^=%&amp;/~\+#])?)", RegexOptions.IgnoreCase);
            MatchCollection linkMatches = linkRegex.Matches(text);
            List<string> matchList = General.MatchCollectionToList(linkMatches);
            foreach (string match in matchList)
            {
                Console.WriteLine("- " + match);
                if (match.Contains("="))
                {
                    Console.WriteLine("-- LFI?");
                    //LFI.Scan(match);
                }
            }
        }
    }
}
