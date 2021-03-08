using System;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;

namespace Reecon
{
    class OSINT_Reddit
    {
        public static RedditInfo GetInfo(string name)
        {
            RedditInfo redditInfo = new RedditInfo { Exists = false };
            var aboutPage = Web.GetHTTPInfo($"https://www.reddit.com/user/{name}/about.json");
            if (aboutPage.StatusCode == HttpStatusCode.OK)
            {
                redditInfo.Exists = true;
                OSINT_Reddit_Profile.Rootobject profile = JsonSerializer.Deserialize<OSINT_Reddit_Profile.Rootobject>(aboutPage.PageText);
                redditInfo.CreationDate = DateTime.FromFileTimeUtc((long)profile.data.created_utc);
                redditInfo.CommentKarma = profile.data.comment_karma;
                var commentsPage = Web.GetHTTPInfo($"https://www.reddit.com/user/{name}/comments.json");
                if (commentsPage.StatusCode == HttpStatusCode.OK)
                {
                    OSINT_Reddit_Comments.Rootobject commentInfo = JsonSerializer.Deserialize<OSINT_Reddit_Comments.Rootobject>(commentsPage.PageText);
                    foreach (var comment in commentInfo.data.children)
                    {
                        redditInfo.CommentList.Add(comment.data);
                    }
                }
            }
            return redditInfo;
        }
    }

    public class RedditInfo
    {
        public bool Exists = false;
        public DateTime CreationDate;
        public int CommentKarma;
        public List<OSINT_Reddit_Comments.Data1> CommentList = new List<OSINT_Reddit_Comments.Data1>();
    }

#pragma warning disable IDE1006 // Naming Styles
    class OSINT_Reddit_Profile
    {
        public class Rootobject
        {
            public string kind { get; set; }
            public Data data { get; set; }
        }

        public class Data
        {
            public bool is_employee { get; set; }
            public bool is_friend { get; set; }
            public Subreddit subreddit { get; set; }
            public object snoovatar_size { get; set; }
            public int awardee_karma { get; set; }
            public string id { get; set; }
            public bool verified { get; set; }
            public bool is_gold { get; set; }
            public bool is_mod { get; set; }
            public int awarder_karma { get; set; }
            public bool has_verified_email { get; set; }
            public string icon_img { get; set; }
            public bool hide_from_robots { get; set; }
            public int link_karma { get; set; }
            public bool pref_show_snoovatar { get; set; }
            public int total_karma { get; set; }
            public bool accept_chats { get; set; }
            public string name { get; set; }
            public float created { get; set; }
            public float created_utc { get; set; }
            public string snoovatar_img { get; set; }
            public int comment_karma { get; set; }
            public bool has_subscribed { get; set; }
            public bool accept_pms { get; set; }
        }

        public class Subreddit
        {
            public bool default_set { get; set; }
            public bool? user_is_contributor { get; set; }
            public string banner_img { get; set; }
            public bool restrict_posting { get; set; }
            public bool? user_is_banned { get; set; }
            public bool free_form_reports { get; set; }
            public object community_icon { get; set; }
            public bool show_media { get; set; }
            public string icon_color { get; set; }
            public bool? user_is_muted { get; set; }
            public string display_name { get; set; }
            public object header_img { get; set; }
            public string title { get; set; }
            public object[] previous_names { get; set; }
            public bool over_18 { get; set; }
            public int[] icon_size { get; set; }
            public string primary_color { get; set; }
            public string icon_img { get; set; }
            public string description { get; set; }
            public string submit_link_label { get; set; }
            public object header_size { get; set; }
            public bool restrict_commenting { get; set; }
            public int subscribers { get; set; }
            public string submit_text_label { get; set; }
            public bool is_default_icon { get; set; }
            public string link_flair_position { get; set; }
            public string display_name_prefixed { get; set; }
            public string key_color { get; set; }
            public string name { get; set; }
            public bool is_default_banner { get; set; }
            public string url { get; set; }
            public bool quarantine { get; set; }
            public object banner_size { get; set; }
            public bool? user_is_moderator { get; set; }
            public string public_description { get; set; }
            public bool link_flair_enabled { get; set; }
            public bool disable_contributor_requests { get; set; }
            public string subreddit_type { get; set; }
            public bool? user_is_subscriber { get; set; }
        }
    }

    public class OSINT_Reddit_Comments
    {
        public class Rootobject
        {
            public string kind { get; set; }
            public Data data { get; set; }
        }

        public class Data
        {
            public string modhash { get; set; }
            public int dist { get; set; }
            public Child[] children { get; set; }
            public object after { get; set; }
            public object before { get; set; }
        }

        public class Child
        {
            public string kind { get; set; }
            public Data1 data { get; set; }
        }

        public class Data1
        {
            public int total_awards_received { get; set; }
            public object approved_at_utc { get; set; }
            public object comment_type { get; set; }
            public object[] awarders { get; set; }
            public object mod_reason_by { get; set; }
            public object banned_by { get; set; }
            public string author_flair_type { get; set; }
            public object removal_reason { get; set; }
            public string link_id { get; set; }
            public object author_flair_template_id { get; set; }
            public object likes { get; set; }
            public string replies { get; set; }
            public object[] user_reports { get; set; }
            public bool saved { get; set; }
            public string id { get; set; }
            public object banned_at_utc { get; set; }
            public object mod_reason_title { get; set; }
            public int gilded { get; set; }
            public bool archived { get; set; }
            public bool no_follow { get; set; }
            public string author { get; set; }
            public int num_comments { get; set; }
            public bool edited { get; set; }
            public bool can_mod_post { get; set; }
            public float created_utc { get; set; }
            public bool send_replies { get; set; }
            public string parent_id { get; set; }
            public int score { get; set; }
            public string author_fullname { get; set; }
            public bool over_18 { get; set; }
            public object[] treatment_tags { get; set; }
            public object approved_by { get; set; }
            public object mod_note { get; set; }
            public object[] all_awardings { get; set; }
            public string subreddit_id { get; set; }
            public string body { get; set; }
            public string link_title { get; set; }
            public object author_flair_css_class { get; set; }
            public string name { get; set; }
            public bool author_patreon_flair { get; set; }
            public int downs { get; set; }
            public object[] author_flair_richtext { get; set; }
            public bool is_submitter { get; set; }
            public string body_html { get; set; }
            public Gildings gildings { get; set; }
            public object collapsed_reason { get; set; }
            public object distinguished { get; set; }
            public object associated_award { get; set; }
            public bool stickied { get; set; }
            public bool author_premium { get; set; }
            public bool can_gild { get; set; }
            public object top_awarded_type { get; set; }
            public object author_flair_text_color { get; set; }
            public bool score_hidden { get; set; }
            public string permalink { get; set; }
            public object num_reports { get; set; }
            public string link_permalink { get; set; }
            public object report_reasons { get; set; }
            public string link_author { get; set; }
            public string subreddit { get; set; }
            public object author_flair_text { get; set; }
            public string link_url { get; set; }
            public float created { get; set; }
            public bool collapsed { get; set; }
            public string subreddit_name_prefixed { get; set; }
            public int controversiality { get; set; }
            public bool locked { get; set; }
            public object author_flair_background_color { get; set; }
            public object collapsed_because_crowd_control { get; set; }
            public object[] mod_reports { get; set; }
            public bool quarantine { get; set; }
            public string subreddit_type { get; set; }
            public int ups { get; set; }
        }

        public class Gildings
        {
        }
    }
#pragma warning restore IDE1006 // Naming Styles
}
