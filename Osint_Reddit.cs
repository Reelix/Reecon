using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;

namespace Reecon
{
    class Osint_Reddit
    {
        public static RedditInfo GetInfo(string name)
        {
            RedditInfo redditInfo = new() { Exists = false };
            var aboutPage = Web.GetHttpInfo($"https://www.reddit.com/user/{name}/about.json", "Reecon (https://github.com/Reelix/reecon)");
            if (aboutPage.StatusCode == HttpStatusCode.OK && aboutPage.PageText != null)
            {
                redditInfo.Exists = true;
                JsonDocument redditProfileInfo = JsonDocument.Parse(aboutPage.PageText);
                JsonElement creationDate = redditProfileInfo.RootElement.GetProperty("data").GetProperty("created_utc");
                JsonElement commentKarma = redditProfileInfo.RootElement.GetProperty("data").GetProperty("comment_karma");
                redditInfo.CreationDate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(creationDate.ToString().Replace(".0", ""))).LocalDateTime;
                redditInfo.CommentKarma = commentKarma.GetInt64();

                // Get Comments
                List<OSINT_Reddit_Comment> commentList = new List<OSINT_Reddit_Comment>();
                var commentsPage = Web.GetHttpInfo($"https://www.reddit.com/user/{name}/comments.json", "Reecon (https://github.com/Reelix/reecon)");
                if (commentsPage.StatusCode == HttpStatusCode.OK && commentsPage.PageText != null)
                {
                    var commentInfo = JsonDocument.Parse(commentsPage.PageText);
                    JsonElement commentChildren = commentInfo.RootElement.GetProperty("data").GetProperty("children");
                    foreach (JsonElement comment in commentChildren.EnumerateArray())
                    {
                        OSINT_Reddit_Comment theComment = new OSINT_Reddit_Comment();
                        JsonElement commentData = comment.GetProperty("data");
                        theComment.Body = commentData.GetProperty("body").ToString();
                        JsonElement commentCreationDate = commentData.GetProperty("created_utc");
                        theComment.Created_UTC = DateTimeOffset.FromUnixTimeSeconds(long.Parse(commentCreationDate.ToString().Replace(".0", ""))).LocalDateTime;
                        theComment.Permalink = commentData.GetProperty("permalink").ToString();
                        commentList.Add(theComment);
                    }
                }
                redditInfo.CommentList = commentList;

                // Get Submissions
                List<OSINT_Reddit_Submission> submissionList = new List<OSINT_Reddit_Submission>();
                try
                {
                    var submissionsPage = Web.GetHttpInfo($"https://www.reddit.com/user/{name}/submitted.json", "Reecon (https://github.com/Reelix/reecon)");
                    if (submissionsPage.StatusCode == HttpStatusCode.OK && submissionsPage.PageText != null)
                    {
                        var submissionInfo = JsonDocument.Parse(submissionsPage.PageText);
                        JsonElement submissionChildren = submissionInfo.RootElement.GetProperty("data").GetProperty("children");
                        foreach (JsonElement submission in submissionChildren.EnumerateArray())
                        {
                            OSINT_Reddit_Submission theSubmission = new OSINT_Reddit_Submission();
                            /*
                            string subreddit;
                            string title;
                            public string selftext;
                            public string URL;
                            public DateTime created_utc;
                            */
                            JsonElement submissionData = submission.GetProperty("data");
                            theSubmission.Subreddit = submissionData.GetProperty("subreddit").ToString();
                            theSubmission.Title = submissionData.GetProperty("title").ToString();
                            theSubmission.Selftext = submissionData.GetProperty("selftext").ToString();
                            theSubmission.URL = submissionData.GetProperty("url").ToString();
                            JsonElement submissionCreationDate = submissionData.GetProperty("created_utc");
                            theSubmission.Created_UTC = DateTimeOffset.FromUnixTimeSeconds(long.Parse(submissionCreationDate.ToString().Replace(".0", ""))).LocalDateTime;
                            submissionList.Add(theSubmission);
                        }
                        redditInfo.SubmissionList = submissionList;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error - Reddit Submitted Format Changed - Bug Reelix - " + ex.Message);
                }
            }

            return redditInfo;
        }
    }

    public class RedditInfo
    {
        public bool Exists;
        public DateTime CreationDate;
        public long CommentKarma;
        public List<OSINT_Reddit_Comment> CommentList = new();
        public List<OSINT_Reddit_Submission> SubmissionList = new();
        // public List<OSINT_Reddit_Submitted> SubmissionList = new();
    }

    public class OSINT_Reddit_Comment
    {
        public string Body = "";
        public DateTime Created_UTC;
        public string Permalink = "";
    }

    public class OSINT_Reddit_Submission
    {
        public string Subreddit = "";
        public string Title = "";
        public string Selftext = "";
        public string URL = "";
        public DateTime Created_UTC;
    }
}
