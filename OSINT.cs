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
            Console.WriteLine("Warning: The OSINT Module is still in early development and will probably break / give incorrect information".Pastel(Color.Red));
            string username = args[1];
            Console.WriteLine("Searching for " + username + "...");
            GetInstagramInfo(username);
            GetRedditInfo(username);
            GetTwitterInfo(username);
            GetYouTubeInfo(username);
            GetGithubInfo(username);
        }

        private static void GetInstagramInfo(string username)
        {
            WebClient wc = new();
            string pageText = wc.DownloadString("https://www.instagram.com/web/search/topsearch/?query=" + username);
            try
            {
                Instagram.Rootobject theObject = JsonSerializer.Deserialize<Instagram.Rootobject>(pageText);
                if (theObject.users == null || theObject.users.Length == 0)
                {
                    Console.WriteLine("- Instagram: Not Found");
                }
                foreach (Instagram.User user in theObject.users)
                {
                    string userUsername = user.user.username;
                    if (userUsername == username || userUsername == username.ToLower())
                    {
                        Console.WriteLine("User ID: " + user.user.pk);
                        Console.WriteLine("Full Name: " + user.user.full_name);
                        Console.WriteLine("Username: " + user.user.username);
                    }
                }
            }
            catch (JsonException jex)
            {
                Console.WriteLine("Instagram OSINT is currently broken - " + jex.Message + " - Bug Reelix!");
            }
        }

        // Pasted as JSON from https://www.instagram.com/web/search/topsearch/?query=Reelix
        public static class Instagram
        {
#pragma warning disable IDE1006 // Naming Styles
            public class Rootobject
            {
                public User[] users { get; set; }
                public Place[] places { get; set; }
                public Hashtag[] hashtags { get; set; }
                public bool has_more { get; set; }
                public string rank_token { get; set; }
                public object clear_client_cache { get; set; }
                public string status { get; set; }
            }

            public class User
            {
                public int position { get; set; }
                public User1 user { get; set; }
            }

            public class User1
            {
                public string pk { get; set; }
                public string username { get; set; }
                public string full_name { get; set; }
                public bool is_private { get; set; }
                public string profile_pic_url { get; set; }
                public string profile_pic_id { get; set; }
                public bool is_verified { get; set; }
                public bool has_anonymous_profile_picture { get; set; }
                public int mutual_followers_count { get; set; }
                public object[] account_badges { get; set; }
                public int latest_reel_media { get; set; }
            }

            public class Place
            {
                public Place1 place { get; set; }
                public int position { get; set; }
            }

            public class Place1
            {
                public Location location { get; set; }
                public string title { get; set; }
                public string subtitle { get; set; }
                public object[] media_bundles { get; set; }
                public string slug { get; set; }
            }

            public class Location
            {
                public string pk { get; set; }
                public string short_name { get; set; }
                public long facebook_places_id { get; set; }
                public string external_source { get; set; }
                public string name { get; set; }
                public string address { get; set; }
                public string city { get; set; }
                public float lng { get; set; }
                public float lat { get; set; }
            }

            public class Hashtag
            {
                public int position { get; set; }
                public Hashtag1 hashtag { get; set; }
            }

            public class Hashtag1
            {
                public string name { get; set; }
                public long id { get; set; }
                public int media_count { get; set; }
                public bool use_default_avatar { get; set; }
                public string profile_pic_url { get; set; }
                public string search_result_subtitle { get; set; }
            }
#pragma warning restore IDE1006 // Naming Styles
        }

        public static void GetRedditInfo(string username)
        {
            var redditInfo = OSINT_Reddit.GetInfo(username);
            if (redditInfo.Exists)
            {
                Console.WriteLine("- Reddit: " + "Found".Pastel(Color.Green));
                Console.WriteLine($"-- Link: https://www.reddit.com/user/{username}");
                // Get Comments
                if (redditInfo.CommentList.Count == 0)
                {
                    Console.WriteLine("-- 0 Comments Made");
                }
                // User has comments - List them
                else
                {
                    foreach (var comment in redditInfo.CommentList)
                    {
                        Console.WriteLine("-- Comment: " + comment.body);
                    }
                }

                // Get submissions
                if (redditInfo.SubmissionList.Count == 0)
                {
                    Console.WriteLine("-- 0 Submissions Made");
                }
                else
                {
                    foreach (var submission in redditInfo.SubmissionList)
                    {
                        Console.WriteLine("-- Submission: " + submission.title);
                        Console.WriteLine("--- Link: " + submission.url);
                        Console.WriteLine("--- Blurb: " + submission.selftext);
                    }
                }
            }
            else
            {
                Console.WriteLine("- Reddit: Not Found");
            }
        }

        private static void GetTwitterInfo(string username)
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
                try
                {
                    Console.WriteLine("-- Name: " + httpInfo.PageTitle.Replace(" on Twitter", ""));

                    // Split into segments
                    string pageText = httpInfo.PageText;
                    List<string> tableList = new();
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
                catch (Exception ex)
                {
                    Console.WriteLine("Twitter OSINT is currently broken - " + ex.Message + " - Bug Reelix!");
                }
            }
            else if (httpInfo.StatusCode == HttpStatusCode.TemporaryRedirect)
            {
                if (httpInfo.Headers.Location != null && httpInfo.Headers.Location.ToString() == "/account/suspended")
                {
                    Console.WriteLine("- Twitter: Account Suspended :<");
                }
            }
            else
            {
                Console.WriteLine("- Twitter: Error - Bug Reelix");
            }
        }

        private static void GetYouTubeInfo(string username)
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
                if (httpInfo.Headers.Location != null)
                {
                    string location = httpInfo.Headers.Location.ToString();
                    if (location.Contains("/user/"))
                    {
                        var userInfo = Web.GetHTTPInfo(location);
                        Console.WriteLine("- YouTube: " + "Found".Pastel(Color.Green));
                        Console.WriteLine("-- User Profile: " + location);
                        Console.WriteLine("-- Name: " + userInfo.PageTitle.Replace(" - YouTube", ""));
                    }
                    else
                    {
                        Console.WriteLine("- YouTube: Unknown Moved to " + httpInfo.Headers.Location.ToString());
                    }
                }
            }
            else
            {
                Console.WriteLine("- YouTube: Error - Bug Reelix: " + httpInfo.StatusCode);
            }
        }

        private static void GetGithubInfo(string username)
        {
            var httpInfo = Web.GetHTTPInfo($"https://api.github.com/users/{username}", "Reecon");
            if (httpInfo.StatusCode == HttpStatusCode.NotFound)
            {
                Console.WriteLine("- Github: Not Found");
            }
            else
            {
                Console.WriteLine("- Github: " + "Found".Pastel(Color.Green));
                var githubInfo = JsonDocument.Parse(httpInfo.PageText);

                JsonElement login = githubInfo.RootElement.GetProperty("login");
                Console.WriteLine("-- Login: " + login);
                JsonElement htmlLink = githubInfo.RootElement.GetProperty("html_url");
                Console.WriteLine($"-- Link: {htmlLink}");
                JsonElement name = githubInfo.RootElement.GetProperty("name");
                Console.WriteLine("-- Name: " + name);
                // TODO: Parse Repos + Commits
                // Repos: https://api.github.com/users/sakurasnowangelaiko/repos
                // Commits (And everything else): https://api.github.com/users/sakurasnowangelaiko/events (
            }
        }
    }
}
