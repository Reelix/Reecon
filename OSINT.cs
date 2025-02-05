using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text.Json;

namespace Reecon
{
    class OSINT
    {
        // This module is completely broken from the in-progress trimming.
        public static void GetInfo(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("OSINT Usage: reecon -osint \"username\"");
                return;
            }
            // Support the weird chars people use on Social Media
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.WriteLine("Warning: The OSINT Module is still in early development and will probably break / give incorrect information".Recolor(Color.Red));
            string username = args[1];
            Console.WriteLine("Searching for " + username + "...");
            //GetInstagramInfo(username); - Broken - https://www.instagram.com/web/search/topsearch/?query=Reelix
            GetRedditInfo(username);
            GetSteamInfo(username);
            //GetTwitterInfo(username);
            // curl https://api.x.com/i/users/email_available.json?email=username@email.com
            // curl https://api.x.com/i/users/username_available.json?username=usernameHere
            GetYouTubeInfo(username);
            GetGithubInfo(username);
            GetPastebinInfo(username);
            // Pastebin - https://pastebin.com/u/rzsdw2iwug77eda
            // TODO: Disqus - https://disqus.com/by/soremanzo/about/ (Comment count + About page)
            // Google Storage: https://storage.googleapis.com/erg1erh315ezf5zev (Note: Malware link - Need a better valid test case)
        }

        /*
        public static void GetInstagramInfo(string username)
        {
            try
            {
                var instagramInfo = OSINT_Instagram.GetInfo(username);
                if (instagramInfo.Exists)
                {
                    foreach (var user in instagramInfo.Users)
                    {
                        Console.WriteLine("-- User ID: " + user.user.pk);
                        Console.WriteLine("-- Full Name: " + user.user.full_name);
                        Console.WriteLine("-- Username: " + user.user.username);
                    }
                }
            }
            catch (JsonException jex)
            {
                Console.WriteLine("Instagram OSINT is currently broken - " + jex.Message + " - Bug Reelix!");
            }
        }
        */

        public static void GetRedditInfo(string username)
        {
            var redditInfo = OSINT_Reddit.GetInfo(username);
            if (redditInfo.Exists)
            {
                Console.WriteLine("- Reddit: " + "Found".Recolor(Color.Green));
                Console.WriteLine($"-- Profile Link: https://www.reddit.com/user/{username}");
                // Get Comments
                if (redditInfo.CommentList.Count == 0)
                {
                    Console.WriteLine("-- 0 Comments Made");
                }
                // User has comments - List them
                else
                {
                    Console.WriteLine("-- " + $"Listing {redditInfo.CommentList.Count} comments".Recolor(Color.Green));
                    foreach (var comment in redditInfo.CommentList)
                    {
                        Console.WriteLine($"-- Comment Link: https://www.reddit.com{comment.Permalink} from {comment.Created_UTC} UTC");
                        string shorterComment = new string(comment.Body.Take(250).ToArray());
                        if (comment.Body.Length > 250)
                        {
                            shorterComment += "... (Snipped due to length)";
                        }
                        Console.WriteLine($"--- Comment: {shorterComment}");
                    }
                }

                // Get submissions
                if (redditInfo.SubmissionList.Count == 0)
                {
                    Console.WriteLine("-- 0 Submissions Made");
                }
                else
                {
                    Console.WriteLine("-- " + $"Listing {redditInfo.SubmissionList.Count} submissions".Recolor(Color.Green));
                    foreach (var submission in redditInfo.SubmissionList)
                    {
                        Console.WriteLine($"-- Submission: {submission.Title} at {submission.URL} from {submission.Created_UTC} UTC");
                        if (submission.Selftext != "")
                        {
                            Console.WriteLine("--- Blurb: " + submission.Selftext);
                        }
                    }
                }

                // New line break at the end
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine("- Reddit: Not Found");
            }
        }

        public static void GetSteamInfo(string username)
        {
            string result = OSINT_Steam.GetInfo(username);
            if (result == "")
            {
                Console.WriteLine("- Steam: Not Found");
            }
            else
            {
                Console.WriteLine("- Steam: " + "Found".Recolor(Color.Green));
                Console.WriteLine(result.Trim(Environment.NewLine.ToCharArray()));

                // New line break at the end
                Console.WriteLine();
            }
        }

        private static void GetTwitterInfo(string username)
        {
            // Twitter usernames don't have spaces
            username = username.Replace(" ", "");
            var httpInfo = Web.GetHTTPInfo($"https://mobile.twitter.com/{username}", "Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.77 Mobile Safari/537.36");
            if (httpInfo.StatusCode == HttpStatusCode.NotFound)
            {
                Console.WriteLine("- Twitter: Not Found");
            }
            else if (httpInfo.StatusCode == HttpStatusCode.OK)
            {
                Console.WriteLine("- Twitter: " + "Found".Recolor(Color.Green));
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
                if (httpInfo.ResponseHeaders.Location != null && httpInfo.ResponseHeaders.Location.ToString() == "/account/suspended")
                {
                    Console.WriteLine("- Twitter: Account Suspended :<");
                }
            }
            else
            {
                Console.WriteLine("- Twitter: " + "Error".Recolor(Color.Red) + " - Bug Reelix");
            }
        }

        private static void GetYouTubeInfo(string username)
        {
            // YouTube usernames CAN have spaces - Oh gawd
            var httpInfo = Web.GetHTTPInfo("https://www.youtube.com/" + username);
            if (httpInfo.StatusCode == HttpStatusCode.OK)
            {
                string youtubeUsername = httpInfo.PageTitle.Replace(" - YouTube", "");
                Console.WriteLine("- YouTube: " + "Found".Recolor(Color.Green));
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

                // New line break at the end
                Console.WriteLine();
            }
            else if (httpInfo.StatusCode == HttpStatusCode.NotFound)
            {
                Console.WriteLine("- YouTube: Not Found");
            }
            else if (httpInfo.StatusCode == HttpStatusCode.Moved)
            {
                if (httpInfo.ResponseHeaders.Location != null)
                {
                    string location = httpInfo.ResponseHeaders.Location.ToString();
                    if (location.Contains("/user/"))
                    {
                        var userInfo = Web.GetHTTPInfo(location);
                        Console.WriteLine("- YouTube: " + "Found".Recolor(Color.Green));
                        Console.WriteLine("-- User Profile: " + location);
                        Console.WriteLine("-- Name: " + userInfo.PageTitle.Replace(" - YouTube", ""));

                        // New line break at the end
                        Console.WriteLine();
                    }
                    else
                    {
                        Console.WriteLine("- YouTube: Unknown Moved to " + httpInfo.ResponseHeaders.Location.ToString());
                    }
                }
            }
            else
            {
                Console.WriteLine("- YouTube: Error - Bug Reelix: " + httpInfo.StatusCode);
            }
        }

        public static void GetGithubInfo(string username)
        {
            var httpInfo = Web.GetHTTPInfo($"https://api.github.com/users/{username}", "Reecon");
            if (httpInfo.StatusCode != HttpStatusCode.NotFound)
            {
                Console.WriteLine("- Github: " + "Found".Recolor(Color.Green));
                var githubInfo = JsonDocument.Parse(httpInfo.PageText);

                JsonElement login = githubInfo.RootElement.GetProperty("login");
                Console.WriteLine("-- Login: " + login);
                JsonElement htmlLink = githubInfo.RootElement.GetProperty("html_url");
                Console.WriteLine($"-- Link: {htmlLink}");
                JsonElement name = githubInfo.RootElement.GetProperty("name");
                Console.WriteLine("-- Name: " + name);
                JsonElement location = githubInfo.RootElement.GetProperty("location");
                if (location.ValueKind != JsonValueKind.Null)
                {
                    Console.WriteLine("-- Location: " + location);
                }
                JsonElement avatar = githubInfo.RootElement.GetProperty("avatar_url");
                if (avatar.ValueKind != JsonValueKind.Null)
                {
                    Console.WriteLine("-- Avatar Picture: " + avatar);
                }
                JsonElement created_at = githubInfo.RootElement.GetProperty("created_at");
                Console.WriteLine("-- Account Created At: " + created_at);
                JsonElement blog = githubInfo.RootElement.GetProperty("blog");
                if (blog.ToString() != "")
                {
                    Console.WriteLine("-- Blog: " + blog);
                }
                // TODO: Parse Repos + Commits
                // Repos: https://api.github.com/users/sakurasnowangelaiko/repos
                // Commits (And everything else): https://api.github.com/users/sakurasnowangelaiko/events (
            }
            else
            {
                Console.WriteLine("- Github: Not Found");
            }
        }

        public static void GetPastebinInfo(string username)
        {
            var httpInfo = Web.GetHTTPInfo($"https://pastebin.com/u/{username}");
            if (httpInfo.StatusCode != HttpStatusCode.NotFound)
            {
                Console.WriteLine("- Pastebin: Found");
                Console.WriteLine($"-- Link: https://pastebin.com/u/{username}");
            }
            else
            {
                Console.WriteLine("- Pastebin: Not Found");
            }
        }
    }
}
