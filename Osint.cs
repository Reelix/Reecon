using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Reecon
{
    internal static class Osint // Open Source Intelligence
    {
        private static readonly HttpClient Client = new();

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
            GetHackerOneInfo(username);
            GetHuggingFaceInfo(username);
            GetInstagramInfo(username);
            GetLinkMeInfo(username);
            GetPastebinInfo(username);
            GetRedditInfo(username);
            // GetRobloxInfo(username) -> curl -s 'https://apis.roblox.com/search-api/omni-search?urlLocale=en_us&verticalType=user&searchQuery=deadcatx3&sessionId=a' | jq
            GetSteamInfo(username);
            GetTelegramInfo(username);
            GetThreadsInfo(username);
            // GetTiktokInfo(username) -- Todo (asdsadsdazzz VS https://www.tiktok.com/@yolosolo17)
            GetTwitterInfo(username);
            GetYouTubeInfo(username);
            // TODO: Disqus - https://disqus.com/by/soremanzo/about/ (Comment count + About page)
            // Google Storage: https://storage.googleapis.com/erg1erh315ezf5zev (Note: Malware link - Need a better valid test case)
        }

        private static void GetGithubInfo(string username)
        {
            var gitHubInfo = Osint_GitHub.GetInfo(username);
            if (gitHubInfo.Exists)
            {
                Console.WriteLine("- GitHub: " + "Found".Recolor(Color.Green));
                Console.WriteLine(gitHubInfo.Info);
            }
            else
            {
                Console.WriteLine("- Github: Not Found");
            }
        }

        private static void GetHackerOneInfo(string username)
        {
            string profileUrl = $"https://hackerone.com/{username}?type=user";
            Web.HttpInfo httpInfo = Web.GetHttpInfo(profileUrl);
            if (httpInfo.StatusCode != HttpStatusCode.NotFound && httpInfo.StatusCode == HttpStatusCode.OK)
            {
                Console.WriteLine("- HackerOne: " + "Found".Recolor(Color.Green));

                // GraphQL Request
                string jsonContent = $$"""
                                       {
                                         "operationName": "UserProfilePageQuery",
                                         "variables": {
                                           "resourceIdentifier": "{{username}}",
                                           "product_area": "other",
                                           "product_feature": "other"
                                         },
                                         "query": "query UserProfilePageQuery($resourceIdentifier: String!) { user(username: $resourceIdentifier) { name } }"
                                       }
                                       """;
                byte[] postData = Encoding.UTF8.GetBytes(jsonContent);
                var contentHeaders = new Dictionary<string, string>
                {
                    { "Content-Type", "application/json" }
                };
                Web.UploadDataResult uploadResult = Web.UploadData("https://hackerone.com/graphql", postData, ContentHeaders: contentHeaders);
                if (uploadResult.StatusCode == HttpStatusCode.OK)
                {
                    string jsonResponse = uploadResult.Text;
                    using JsonDocument doc = JsonDocument.Parse(jsonResponse);
                    string? name = doc.RootElement.GetProperty("data").GetProperty("user").GetProperty("name").GetString();
                    if (name != null)
                    {
                        Console.WriteLine($"-- Name: {name}");
                    }
                    else
                    {
                        Console.WriteLine("-- Name is empty - Bug Reelix to get additional HackerOne info.");
                    }
                }
            }
            else
            {
                Console.WriteLine("- HackerOne: Not Found");
            }
        }

        private static void GetHuggingFaceInfo(string username)
        {
            string profileUrl = $"https://huggingface.co/{username}";
            Web.HttpInfo httpInfo = Web.GetHttpInfo(profileUrl, AllowAutoRedirect: true);
            if (httpInfo.StatusCode != HttpStatusCode.NotFound && httpInfo.PageText != null)
            {
                Console.WriteLine("- HuggingFace: " + "Found".Recolor(Color.Green));
                string pageText = httpInfo.PageText;
                // Pull out the User Profile blob
                string userProfileJsonRaw = pageText.Remove(0, pageText.IndexOf("data-target=\"UserProfile\"", StringComparison.Ordinal) + 38);
                userProfileJsonRaw = userProfileJsonRaw.Substring(0, userProfileJsonRaw.IndexOf("\"><div", StringComparison.Ordinal));
                // Decode it
                string userProfileJson = WebUtility.HtmlDecode(userProfileJsonRaw);
                // And parse it
                using JsonDocument doc = JsonDocument.Parse(userProfileJson);
                JsonElement userProfile = doc.RootElement.GetProperty("u");
                string? siteUsername = userProfile.GetProperty("user").GetString();
                if (siteUsername != null)
                {
                    Console.WriteLine($"-- Link: https://huggingface.co/{siteUsername}");
                }

                string? siteFullname = userProfile.GetProperty("fullname").GetString();
                if (siteFullname != null)
                {
                    Console.WriteLine($"-- Full Name: {siteFullname}");
                }

                JsonElement userSocials = userProfile.GetProperty("signup");
                foreach (var item in userSocials.EnumerateObject())
                {
                    string socialName = item.Name;
                    string? socialValue = item.Value.GetString();
                    Console.WriteLine($"-- {socialName}: {socialValue}");
                }
            }
            else
            {
                Console.WriteLine("- HuggingFace: Not Found");
            }
        }

        private static void GetInstagramInfo(string username)
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
                Console.WriteLine(result);
            }
        }

        private static void GetTelegramInfo(string username)
        {
            Web.HttpInfo httpInfo = Web.GetHttpInfo($"https://t.me/{username}");
            if (httpInfo.StatusCode != HttpStatusCode.NotFound && httpInfo.PageText != null && httpInfo.PageText.Contains("tgme_page_extra"))
            {
                string pageExtra = httpInfo.PageText.Remove(0, httpInfo.PageText.IndexOf("tgme_page_extra", StringComparison.Ordinal) + 17);
                pageExtra = pageExtra.Substring(0, pageExtra.IndexOf("</div>", StringComparison.Ordinal));
                pageExtra = pageExtra.Replace(Environment.NewLine, "").Trim();

                if (pageExtra.StartsWith('@'))
                {
                    Console.WriteLine("- Telegram (User): " + "Found".Recolor(Color.Green));
                    // Username
                    string name = httpInfo.PageText.Remove(0, httpInfo.PageText.IndexOf("tgme_page_title", StringComparison.Ordinal) + 15);
                    // Span inside
                    name = name.Remove(0, name.IndexOf("<span dir = \"auto\">", StringComparison.Ordinal) + 20);
                    name = name.Substring(0, name.IndexOf("</span>", StringComparison.Ordinal));
                    Console.WriteLine($"-- Name: {name}");
                }
                else if (pageExtra.EndsWith("subscribers"))
                {
                    Console.WriteLine("- Telegram (Channel): " + "Found".Recolor(Color.Green));
                }
                else if (pageExtra.Contains(" members ") && pageExtra.Contains(" online"))
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
                    Console.WriteLine("-- Twitter OSINT is currently broken - " + ex.Message + " - Bug Reelix!");
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
                Console.WriteLine("-- Twitter: " + "Error".Recolor(Color.Red) + " - Bug Reelix");
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