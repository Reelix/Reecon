using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Reecon
{
    class OSINT_Reddit
    {
        public static RedditInfo GetInfo(string name)
        {
            RedditInfo redditInfo = new() { Exists = false };
            var aboutPage = Web.GetHTTPInfo($"https://www.reddit.com/user/{name}/about.json", "Reecon (https://github.com/Reelix/reecon)");
            if (aboutPage.StatusCode == HttpStatusCode.OK)
            {
                redditInfo.Exists = true;
                var redditProfileInfo = JsonDocument.Parse(aboutPage.PageText);
                JsonElement creationDate = redditProfileInfo.RootElement.GetProperty("data").GetProperty("created_utc");
                JsonElement commentKarma = redditProfileInfo.RootElement.GetProperty("data").GetProperty("comment_karma");
                redditInfo.CreationDate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(creationDate.ToString().Replace(".0", ""))).LocalDateTime;
                redditInfo.CommentKarma = commentKarma.GetInt64();

                // Get Comments
                List<OSINT_Reddit_Comment> commentList = new List<OSINT_Reddit_Comment>();
                var commentsPage = Web.GetHTTPInfo($"https://www.reddit.com/user/{name}/comments.json", "Reecon (https://github.com/Reelix/reecon)");
                if (commentsPage.StatusCode == HttpStatusCode.OK)
                {
                    var commentInfo = JsonDocument.Parse(commentsPage.PageText);
                    JsonElement commentChildren = commentInfo.RootElement.GetProperty("data").GetProperty("children");
                    foreach (JsonElement comment in commentChildren.EnumerateArray())
                    {
                        OSINT_Reddit_Comment theComment = new OSINT_Reddit_Comment();
                        theComment.body = comment.GetProperty("data").GetProperty("body").ToString();
                        JsonElement commentCreationDate = comment.GetProperty("data").GetProperty("created_utc");
                        theComment.created_utc = DateTimeOffset.FromUnixTimeSeconds(long.Parse(commentCreationDate.ToString().Replace(".0", ""))).LocalDateTime;
                        theComment.permalink = comment.GetProperty("data").GetProperty("permalink").ToString();
                        commentList.Add(theComment);
                    }
                }
                redditInfo.CommentList = commentList;

                // Get Submissions
                /*
                try
                {
                    var submissionsPage = Web.GetHTTPInfo($"https://www.reddit.com/user/{name}/submitted.json");
                    if (submissionsPage.StatusCode == HttpStatusCode.OK)
                    {
                        OSINT_Reddit_Submitted.Rootobject submissionInfo = JsonSerializer.Deserialize(submissionsPage.PageText, typeof(OSINT_Reddit_Submitted.Rootobject)) as OSINT_Reddit_Submitted.Rootobject;
                        foreach (var submission in submissionInfo.data.children)
                        {
                            redditInfo.SubmissionList.Add(submission.data);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error - Reddit Submitted Format Changed - Bug Reelix - " + ex.Message);
                }
                */
            }

            return redditInfo;
        }
    }

    public class RedditInfo
    {
        public bool Exists = false;
        public DateTime CreationDate;
        public long CommentKarma;
        public List<OSINT_Reddit_Comment> CommentList = new();
        // public List<OSINT_Reddit_Submitted> SubmissionList = new();
    }

    public class OSINT_Reddit_Comment
    {
        public string body;
        public DateTime created_utc;
        public string permalink;
    }
}
