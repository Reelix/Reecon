using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;

namespace Reecon
{
    class OSINT_Steam
    {
        public static string GetInfo(string name)
        {
            // TODO: Fix layout bug - ChuckLephuck
            // Direct profile
            string profileName = GetProfileName(name);

            // Search
            string searchResult = GetSearchInfo(name);
            return profileName + Environment.NewLine + searchResult;
        }

        private static string GetProfileName(string name)
        {
            if (name.Contains(" "))
            {
                // Steam usernames cannot contain spaces
                return "";
            }
            string profileText = Web.DownloadString($"https://steamcommunity.com/id/{name}");
            if (profileText.Contains("<bdi>") && !profileText.Contains("<bdi></bdi>"))
            {
                string profileName = profileText.Remove(0, profileText.IndexOf("<bdi>") + 5);
                profileName = profileName.Substring(0, profileName.IndexOf("</bdi>"));
                return $"-- Profile: https://steamcommunity.com/id/{name}" + Environment.NewLine + "-- Real Name: " + profileName;
            }
            return "";
        }

        private static string GetSearchInfo(string name)
        {
            string toReturn = "";
            string pageText = Web.DownloadString("https://steamcommunity.com/search/users/");
            string sessionValue = pageText.Remove(0, pageText.IndexOf("g_sessionID = \"") + 15);
            sessionValue = sessionValue.Substring(0, sessionValue.IndexOf("\""));

            pageText = Web.DownloadString($"https://steamcommunity.com/search/SearchCommunityAjax?text={name}&filter=users&sessionid={sessionValue}", Cookie: $"sessionid={sessionValue}");
            OSINT_Steam_Search searchResults = JsonSerializer.Deserialize<OSINT_Steam_Search>(pageText);
            string htmlResult = searchResults.html;
            htmlResult = htmlResult.Remove(0, htmlResult.IndexOf("<a class=\"searchPersonaName\""));
            List<string> resultList = htmlResult.Split("<a class=\"searchPersonaName\"", StringSplitOptions.RemoveEmptyEntries).ToList();
            foreach (string result in resultList)
            {
                // We also have their country - We can ignore that for now - Maybe later
                // 2 options - /profiles/ or /id/
                string profileLink = "";
                if (result.Contains("https://steamcommunity.com/profiles/"))
                {
                    profileLink = result.Remove(0, result.IndexOf("https://steamcommunity.com/profiles/"));
                }
                else if (result.Contains("https://steamcommunity.com/id/"))
                {
                    profileLink = result.Remove(0, result.IndexOf("https://steamcommunity.com/id/"));
                }
                else
                {
                    Console.WriteLine("Error in OSINT_Steam.GetSearchInfo - Bug Reelix!");
                    return "";
                }
                string steamLink = profileLink.Substring(0, profileLink.IndexOf("\""));
                if (steamLink == $"https://steamcommunity.com/id/{name}")
                {
                    // Match of the first - Ignore it
                    continue;
                }
                string steamName = profileLink.Remove(0, profileLink.IndexOf(">") + 1);
                steamName = steamName.Substring(0, steamName.IndexOf("<")); // Hope we don't have anyone with a > in their name
                toReturn += $"-- Possible Match: {steamName} -> {steamLink}";
            }
            return toReturn;
        }
    }

    public class OSINT_Steam_Search
    {
        public int success { get; set; }
        public string search_text { get; set; }
        public int search_result_count { get; set; }
        public string search_filter { get; set; }
        public int search_page { get; set; }
        public string html { get; set; }
    }

}
