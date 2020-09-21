using Pastel;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text.Json;

namespace Reecon
{
    class OSINT
    {
        public static void GetInfo(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("OSINT Usage: reecon -osint \"username\"");
                return;
            }
            // Support the weird chars people use on Social Media
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            string username = args[1];
            Instagram(username);
            Twitter(username);
            YouTube(username);
        }

        private static void Instagram(string username)
        {
            // Instagram usernames don't have spaces
            username = username.Replace(" ", "");
            var httpInfo = Web.GetHTTPInfo("https://www.instagram.com/" + username + "/?__a=1");
            if (httpInfo.StatusCode == HttpStatusCode.NotFound)
            {
                Console.WriteLine("- Instagram: Not Found");
            }
            else if (httpInfo.StatusCode == HttpStatusCode.OK)
            {
                string pageText = httpInfo.PageText;
                Console.WriteLine("- Instagram: " + "Found".Pastel(Color.Green));
                Console.WriteLine("-- Link: https://www.instagram.com/" + username + "/");
                var document = JsonDocument.Parse(pageText);
                // Oh gawd
                foreach (var item in document.RootElement.EnumerateObject())
                {
                    if (item.Name == "graphql")
                    {
                        foreach (var graphitem in item.Value.EnumerateObject())
                        {
                            if (graphitem.Name == "user")
                            {
                                foreach (var userItem in graphitem.Value.EnumerateObject())
                                {
                                    if (userItem.Name == "biography")
                                    {
                                        string biography = userItem.Value.GetString().Replace("\n", " -- ");
                                        if (biography.Trim() != "")
                                        {
                                            Console.WriteLine("-- Biography: " + userItem.Value.GetString().Replace("\n", " -- "));
                                        }
                                    }
                                    if (userItem.Name == "full_name")
                                    {
                                        if (userItem.Value.ToString().Trim() != "")
                                        {
                                            Console.WriteLine("-- Full Name: " + userItem.Value);
                                        }
                                    }
                                    if (userItem.Name == "edge_owner_to_timeline_media")
                                    {
                                        foreach (var posts in userItem.Value.EnumerateObject())
                                        {
                                            if (posts.Name == "count")
                                            {
                                                Console.WriteLine("-- Posts: " + posts.Value);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            }
            else
            {
                Console.WriteLine("- Instagram: Error - Bug Reelix");
            }
        }

        private static void Twitter(string username)
        {
            // Twitter usernames don't have spaces
            username = username.Replace(" ", "");
            var httpInfo = Web.GetHTTPInfo("https://mobile.twitter.com/" + username);
            if (httpInfo.StatusCode == HttpStatusCode.NotFound)
            {
                Console.WriteLine("- Twitter: Not Found");
            }
            else if (httpInfo.StatusCode == HttpStatusCode.OK)
            {
                Console.WriteLine("- Twitter: " + "Found".Pastel(Color.Green));
                Console.WriteLine("-- Link: https://www.twitter.com/" + username);

                // Profile name
                Console.WriteLine("-- Name: " + httpInfo.PageTitle.Replace(" on Twitter", ""));

                // Split into segments
                string pageText = httpInfo.PageText;
                List<string> tableList = new List<string>();
                tableList.AddRange(pageText.Split("<table", StringSplitOptions.RemoveEmptyEntries));

                // Find Bio
                string profileInfo = tableList.First(x => x.Trim().StartsWith("class=\"profile-details\">"));
                string bio = profileInfo.Remove(0, profileInfo.IndexOf("<div class=\"bio\">") + 58);
                bio = bio.Substring(0, bio.IndexOf("</div>")).Trim();
                if (bio.Trim() != "")
                {
                    Console.WriteLine("-- Bio: " + bio);
                }

                // Find Stats
                string profileStats = tableList.First(x => x.Trim().StartsWith("class=\"profile-stats\">"));
                List<string> statList = profileStats.Split("<td", StringSplitOptions.RemoveEmptyEntries).ToList();
                // 0 = N/A, 1 = Tweets, 2 = Following, 3 = Followers
                string tweetCount = statList[1].Remove(0, statList[1].IndexOf("statnum") + 9);
                tweetCount = tweetCount.Substring(0, tweetCount.IndexOf("<"));
                Console.WriteLine("-- Tweets: " + tweetCount);

                // Tweets - To do
                // List<string> tweetCount = tableList.Count(x => x.Trim().StartsWith("class=\"tweet  \"")).ToList();
                // Console.WriteLine("-- Tweets: " + tweetCount + (tweetCount == 20 ? "+" : ""));
            }
            else if (httpInfo.StatusCode == HttpStatusCode.TemporaryRedirect)
            {
                if (httpInfo.Headers["Location"] != null && httpInfo.Headers["Location"] == "/account/suspended")
                {
                    Console.WriteLine("- Twitter: Account Suspended :<");
                }
            }
            else
            {
                Console.WriteLine("- Twitter: Error - Bug Reelix");
            }
        }

        private static void YouTube(string username)
        {
            // YouTube usernames CAN have spaces - Oh gawd
            var httpInfo = Web.GetHTTPInfo("https://www.youtube.com/" + username);
            if (httpInfo.StatusCode == HttpStatusCode.OK)
            {

                string youtubeUsername = httpInfo.PageTitle.Replace(" - YouTube", "");
                Console.WriteLine("- YouTube: " + "Found".Pastel(Color.Green));
                Console.WriteLine("-- Link: https://www.youtube.com/" + username);
                Console.WriteLine("-- Name: " + youtubeUsername);

                // About page
                var aboutPage = Web.GetHTTPInfo("https://www.youtube.com/c/" + username + "/about");

                // Description
                string description = aboutPage.PageText;
                description = description.Remove(0, description.IndexOf("og:description") + 25);
                description = description.Substring(0, description.IndexOf("\">"));
                if (description.Trim() != "")
                {
                    Console.WriteLine("-- Description: " + description);
                }
            }
            else if (httpInfo.StatusCode == HttpStatusCode.NotFound)
            {
                Console.WriteLine("- YouTube: Not Found");
            }
            else if (httpInfo.StatusCode == HttpStatusCode.Moved)
            {
                if (httpInfo.Headers["Location"] != null)
                {
                    string location = httpInfo.Headers["Location"];
                    if (location.Contains("/user/"))
                    {
                        var userInfo = Web.GetHTTPInfo(location);
                        Console.WriteLine("- YouTube: " + "Found".Pastel(Color.Green));
                        Console.WriteLine("-- User Profile: " + location);
                        Console.WriteLine("-- Name: " + userInfo.PageTitle.Replace(" - YouTube", ""));
                    }
                    else
                    {
                        Console.WriteLine("- YouTube: Unknown Moved to " + httpInfo.Headers["Location"]);
                    }
                }
            }
            else
            {
                Console.WriteLine("- YouTube: Error - Bug Reelix: " + httpInfo.StatusCode);
            }
        }
    }
}
