using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text.Json;

namespace Reecon
{
    internal static class Osint // Open Source Intelligence
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
            Console.WriteLine($"Searching for {username}...");
            
            // Keep this in alphabetical order
            
            GetGithubInfo(username);
            // GetInstagramInfo(username); - Broken
            // https://www.instagram.com/web/search/topsearch/?query=Reelix
            // Requires any ds_user_id value, and a valid session token...
            GetLinkMeInfo(username);
            GetPastebinInfo(username);
            GetRecRoomInfo(username);
            GetRedditInfo(username);
            GetSteamInfo(username);
            GetThreadsInfo(username);
            GetInstagramInfo2(username);
            // GetTelegramInfo(username);
            GetTwitterInfo(username);
            GetYouTubeInfo(username);
            // TODO: Disqus - https://disqus.com/by/soremanzo/about/ (Comment count + About page)
            // Google Storage: https://storage.googleapis.com/erg1erh315ezf5zev (Note: Malware link - Need a better valid test case)
        }

        private static void GetGithubInfo(string username)
        {
            Web.HttpInfo httpInfo = Web.GetHttpInfo($"https://api.github.com/users/{username}", "Reecon");
            if (httpInfo.StatusCode != HttpStatusCode.NotFound && httpInfo.PageText != null)
            {
                Console.WriteLine("- Github: " + "Found".Recolor(Color.Green));
                JsonDocument githubInfo = JsonDocument.Parse(httpInfo.PageText);

                JsonElement login = githubInfo.RootElement.GetProperty("login");
                Console.WriteLine("-- Login: " + login);
                JsonElement htmlLink = githubInfo.RootElement.GetProperty("html_url");
                Console.WriteLine($"-- Link: {htmlLink}");
                JsonElement name = githubInfo.RootElement.GetProperty("name");
                Console.WriteLine("-- Name: " + name);
                // Bio?
                JsonElement company = githubInfo.RootElement.GetProperty("company");
                if (company.ValueKind != JsonValueKind.Null)
                {
                    Console.WriteLine("-- Company: " + company);
                }
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
                JsonElement createdAt = githubInfo.RootElement.GetProperty("created_at");
                Console.WriteLine("-- Account Created At: " + createdAt);
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

        private static void GetInstagramInfo2(string username)
        {
            string profileUrl = $"https://www.instagram.com/{username}";
            Web.HttpInfo httpInfo = Web.GetHttpInfo(profileUrl);
            if (httpInfo.StatusCode != HttpStatusCode.NotFound && httpInfo.StatusCode == HttpStatusCode.OK)
            {
                // It's hacky - But it works :p
                if (httpInfo.ResponseHeaders.FirstOrDefault(x => x.Key == "document-policy").Value.Count() == 2)
                {
                    Console.WriteLine("- Instagram: " + "Found".Recolor(Color.Green));
                    Console.WriteLine($"-- Profile Link: {profileUrl}");
                }
                else
                {
                    Console.WriteLine("- Instagram: Not Found");
                }
            }
        }
        
        private static void GetLinkMeInfo(string username)
        {
            Web.HttpInfo httpInfo = Web.GetHttpInfo($"https://link.me/{username}");
            if (httpInfo.StatusCode != HttpStatusCode.NotFound)
            {
                Console.WriteLine("- Link Me: " + "Found".Recolor(Color.Green));
                Console.WriteLine($"-- Link: https://link.me/{username}");
            }
            else
            {
                Console.WriteLine("- Link Me: Not Found");
            }
        }

        private static void GetPastebinInfo(string username)
        {
            Web.HttpInfo httpInfo = Web.GetHttpInfo($"https://pastebin.com/u/{username}");
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

        private static void GetRecRoomInfo(string username)
        {
            Web.HttpInfo httpInfo = Web.GetHttpInfo($"https://apim.rec.net/accounts/account?username={username}");
            if (httpInfo.StatusCode != HttpStatusCode.NotFound && httpInfo.PageText != null)
            {
                Console.WriteLine("- Rec Room: " + "Found".Recolor(Color.Green));
                Console.WriteLine($"-- Link: https://rec.net/user/{username}");
            }
            else
            {
                Console.WriteLine("- Rec Room: Not Found");
            }
        }
        
        private static void GetRedditInfo(string username)
        {
            RedditInfo redditInfo = Osint_Reddit.GetInfo(username);
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
                    foreach (OSINT_Reddit_Comment comment in redditInfo.CommentList)
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
                    foreach (OSINT_Reddit_Submission submission in redditInfo.SubmissionList)
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
        
        private static void GetSteamInfo(string username)
        {
            string result = Osint_Steam.GetInfo(username);
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

        private static void GetThreadsInfo(string username)
        {
            string profileUrl = $"https://www.threads.com/@{username}";
            Web.HttpInfo httpInfo = Web.GetHttpInfo(profileUrl);
            if (httpInfo.StatusCode != HttpStatusCode.NotFound && httpInfo.StatusCode == HttpStatusCode.OK) // Threads redirects if the profile doesn't exist
            {
                Console.WriteLine("- Threads: " + "Found".Recolor(Color.Green));
                Console.WriteLine($"-- Profile Link: {profileUrl}");
            }
            else
            {
                Console.WriteLine("- Threads: Not Found");
            }
        }

        public static void GetTelegramInfo(string username)
        {
            Web.HttpInfo httpInfo = Web.GetHttpInfo($"https://t.me/{username}");
            if (httpInfo.StatusCode != HttpStatusCode.NotFound && httpInfo.PageText != null && httpInfo.PageText.Contains("tgme_page_extra"))
            {
                string pageExtra = httpInfo.PageText.Remove(0, httpInfo.PageText.IndexOf("tgme_page_extra", StringComparison.Ordinal) + 17);
                pageExtra = pageExtra.Substring(0, pageExtra.IndexOf("</div>", StringComparison.Ordinal));
                pageExtra = pageExtra.Replace(Environment.NewLine, "").Trim();
                
                // Name is in tgme_page_title - May do that later
                if (pageExtra.StartsWith('@'))
                {
                    // Username
                    Console.WriteLine("- Telegram (User): " + "Found".Recolor(Color.Green));
                    string name = httpInfo.PageText.Remove(0,  httpInfo.PageText.IndexOf("tgme_page_title", StringComparison.Ordinal) + 15);
                    // Span inside
                    name = name.Remove(0, name.IndexOf("<span dir = \"auto\">", StringComparison.Ordinal) + 20);
                    name = name.Substring(0, name.IndexOf("</span>", StringComparison.Ordinal));
                    Console.WriteLine($"-- Name: {name}");
                }
                else if (pageExtra.EndsWith("subscribers"))
                {
                    Console.WriteLine("- Telegram (Group): " + "Found".Recolor(Color.Green));
                }
                Console.WriteLine($"-- Link: https://t.me/{username}");
            }
            else
            {
                Console.WriteLine("- Telegram: Not Found");
            }
        }
        
        private static void GetTwitterInfo(string username)
        {
            // TODO
            // curl https://api.x.com/i/users/email_available.json?email=username@email.com
            // curl https://api.x.com/i/users/username_available.json?username=usernameHere

            // Twitter usernames don't have spaces

            username = username.Replace(" ", "");
            Web.HttpInfo httpInfo = Web.GetHttpInfo($"https://x.com/{username}", "Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.77 Mobile Safari/537.36");
            if (httpInfo.StatusCode == HttpStatusCode.NotFound)
            {
                Console.WriteLine("- Twitter: Not Found");
            }
            else if (httpInfo.StatusCode == HttpStatusCode.OK && httpInfo.PageTitle != null && httpInfo.PageText != null)
            {
                Console.WriteLine("- Twitter: " + "Found".Recolor(Color.Green));
                Console.WriteLine("-- Link: https://x.com/" + username);

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
                    string bio = profileInfo.Remove(0, profileInfo.IndexOf("<div class=\"bio\">", StringComparison.Ordinal) + 58);
                    bio = bio.Substring(0, bio.IndexOf("</div>", StringComparison.Ordinal)).Trim();
                    if (bio.Trim() != "")
                    {
                        Console.WriteLine("-- Bio: " + bio);
                    }

                    // Find Stats
                    string profileStats = tableList.First(x => x.Trim().StartsWith("class=\"profile-stats\">"));
                    List<string> statList = profileStats.Split("<td", StringSplitOptions.RemoveEmptyEntries).ToList();
                    // 0 = N/A, 1 = Tweets, 2 = Following, 3 = Followers
                    string tweetCount = statList[1].Remove(0, statList[1].IndexOf("statnum", StringComparison.Ordinal) + 9);
                    tweetCount = tweetCount.Substring(0, tweetCount.IndexOf('<'));
                    Console.WriteLine("-- Tweets: " + tweetCount);

                    // Tweets - To do
                    // List<string> tweetCount = tableList.Count(x => x.Trim().StartsWith("class=\"tweet  \"")).ToList();
                    // Console.WriteLine("-- Tweets: " + tweetCount + (tweetCount == 20 ? "+" : ""));
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Twitter OSINT is currently broken - " + ex.Message + " - Bug Reelix!");
                    General.HandleUnknownException(ex);
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
            // YouTube can be both youtube.com/user OR youtube.com/@user
            Web.HttpInfo httpInfo = Web.GetHttpInfo("https://www.youtube.com/" + username);
            if (httpInfo.StatusCode == HttpStatusCode.OK && httpInfo.PageTitle != null)
            {
                string youtubeUsername = httpInfo.PageTitle.Replace(" - YouTube", "");
                Console.WriteLine("- YouTube: " + "Found".Recolor(Color.Green));
                Console.WriteLine($"-- Link: https://www.youtube.com/{username}");
                Console.WriteLine($"-- Name: {youtubeUsername}");

                // About page
                Web.HttpInfo aboutPage = Web.GetHttpInfo("https://www.youtube.com/c/" + username + "/about");
                if (aboutPage.StatusCode == HttpStatusCode.OK && aboutPage.PageText != null)
                {
                    // Description
                    string description = aboutPage.PageText;
                    description = description.Remove(0, description.IndexOf("og:description", StringComparison.Ordinal) + 25);
                    description = description.Substring(0, description.IndexOf("\">", StringComparison.Ordinal));
                    if (description.Trim() != "")
                    {
                        Console.WriteLine("-- Description: " + description);
                    }
                }
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
                        Web.HttpInfo userInfo = Web.GetHttpInfo(location);
                        if (userInfo.StatusCode == HttpStatusCode.OK && userInfo.PageTitle != null)
                        {
                            Console.WriteLine("- YouTube: " + "Found".Recolor(Color.Green));
                            Console.WriteLine("-- User Profile: " + location);
                            Console.WriteLine("-- Name: " + userInfo.PageTitle.Replace(" - YouTube", ""));
                        }

                        // New line break at the end
                        Console.WriteLine();
                    }
                    else
                    {
                        Console.WriteLine("- YouTube: Unknown Moved to " + httpInfo.ResponseHeaders.Location);
                    }
                }
            }
            else
            {
                Console.WriteLine("- YouTube: Error - Bug Reelix: " + httpInfo.StatusCode);
            }
            
            // .com/@{username} is different from .com/{username} ._.
            
            httpInfo = Web.GetHttpInfo("https://www.youtube.com/@" + username);
            if (httpInfo.StatusCode == HttpStatusCode.OK && httpInfo.PageTitle != null)
            {
                Console.WriteLine("- YouTube - User: " + "Found".Recolor(Color.Green));
                Console.WriteLine($"-- Link: https://www.youtube.com/@{username}");
            }
        }
    }
}
