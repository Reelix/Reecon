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
            RedditInfo redditInfo = new() { Exists = false };
            var aboutPage = Web.GetHTTPInfo($"https://www.reddit.com/user/{name}/about.json", "Reecon");
            if (aboutPage.StatusCode == HttpStatusCode.OK)
            {
                redditInfo.Exists = true;
                OSINT_Reddit_Profile.Rootobject profile = JsonSerializer.Deserialize<OSINT_Reddit_Profile.Rootobject>(aboutPage.PageText);
                redditInfo.CreationDate = DateTime.FromFileTimeUtc((long)profile.data.created_utc);
                redditInfo.CommentKarma = profile.data.comment_karma;

                // Get Comments
                var commentsPage = Web.GetHTTPInfo($"https://www.reddit.com/user/{name}/comments.json");
                if (commentsPage.StatusCode == HttpStatusCode.OK)
                {
                    OSINT_Reddit_Comments.Rootobject commentInfo = JsonSerializer.Deserialize<OSINT_Reddit_Comments.Rootobject>(commentsPage.PageText);
                    foreach (var comment in commentInfo.data.children)
                    {
                        redditInfo.CommentList.Add(comment.data);
                    }
                }

                // Get Submissions
                try
                {
                    var submissionsPage = Web.GetHTTPInfo($"https://www.reddit.com/user/{name}/submitted.json");
                    if (submissionsPage.StatusCode == HttpStatusCode.OK)
                    {
                        OSINT_Reddit_Submitted.Rootobject submissionInfo = JsonSerializer.Deserialize<OSINT_Reddit_Submitted.Rootobject>(submissionsPage.PageText);
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
            }
            return redditInfo;
        }
    }

    public class RedditInfo
    {
        public bool Exists = false;
        public DateTime CreationDate;
        public int CommentKarma;
        public List<OSINT_Reddit_Comments.Data1> CommentList = new();
        public List<OSINT_Reddit_Submitted.Data1> SubmissionList = new();
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

    public class OSINT_Reddit_Submitted
    {
        public class Rootobject
        {
            public string kind { get; set; }
            public Data data { get; set; }
        }

        public class Data
        {
            public string after { get; set; }
            public int dist { get; set; }
            public string modhash { get; set; }
            public string geo_filter { get; set; }
            public Child[] children { get; set; }
            public object before { get; set; }
        }

        public class Child
        {
            public string kind { get; set; }
            public Data1 data { get; set; }
        }

        public class Data1
        {
            public object approved_at_utc { get; set; }
            public string subreddit { get; set; }
            public string selftext { get; set; }
            public string author_fullname { get; set; }
            public bool saved { get; set; }
            public object mod_reason_title { get; set; }
            public int gilded { get; set; }
            public bool clicked { get; set; }
            public string title { get; set; }
            public Link_Flair_Richtext[] link_flair_richtext { get; set; }
            public string subreddit_name_prefixed { get; set; }
            public bool hidden { get; set; }
            public int? pwls { get; set; }
            public string link_flair_css_class { get; set; }
            public int downs { get; set; }
            public int? thumbnail_height { get; set; }
            public object top_awarded_type { get; set; }
            public bool hide_score { get; set; }
            public string name { get; set; }
            public bool quarantine { get; set; }
            public string link_flair_text_color { get; set; }
            public float upvote_ratio { get; set; }
            public string author_flair_background_color { get; set; }
            public int ups { get; set; }
            public int total_awards_received { get; set; }
            public Media_Embed media_embed { get; set; }
            public int? thumbnail_width { get; set; }
            public string author_flair_template_id { get; set; }
            public bool is_original_content { get; set; }
            public object[] user_reports { get; set; }
            public Secure_Media secure_media { get; set; }
            public bool is_reddit_media_domain { get; set; }
            public bool is_meta { get; set; }
            public object category { get; set; }
            public Secure_Media_Embed secure_media_embed { get; set; }
            public string link_flair_text { get; set; }
            public bool can_mod_post { get; set; }
            public int score { get; set; }
            public object approved_by { get; set; }
            public bool is_created_from_ads_ui { get; set; }
            public bool author_premium { get; set; }
            public string thumbnail { get; set; }
            public object edited { get; set; }
            public string author_flair_css_class { get; set; }
            public Author_Flair_Richtext[] author_flair_richtext { get; set; }
            public Gildings gildings { get; set; }
            public string post_hint { get; set; }
            public object content_categories { get; set; }
            public bool is_self { get; set; }
            public string subreddit_type { get; set; }
            public float created { get; set; }
            public string link_flair_type { get; set; }
            public int? wls { get; set; }
            public string removed_by_category { get; set; }
            public object banned_by { get; set; }
            public string author_flair_type { get; set; }
            public string domain { get; set; }
            public bool allow_live_comments { get; set; }
            public string selftext_html { get; set; }
            public bool? likes { get; set; }
            public string suggested_sort { get; set; }
            public object banned_at_utc { get; set; }
            public object view_count { get; set; }
            public bool archived { get; set; }
            public bool no_follow { get; set; }
            public bool is_crosspostable { get; set; }
            public bool pinned { get; set; }
            public bool over_18 { get; set; }
            public Preview preview { get; set; }
            public All_Awardings[] all_awardings { get; set; }
            public object[] awarders { get; set; }
            public bool media_only { get; set; }
            public string link_flair_template_id { get; set; }
            public bool can_gild { get; set; }
            public bool spoiler { get; set; }
            public bool locked { get; set; }
            public string author_flair_text { get; set; }
            public object[] treatment_tags { get; set; }
            public string rte_mode { get; set; }
            public bool visited { get; set; }
            public object removed_by { get; set; }
            public object mod_note { get; set; }
            public object distinguished { get; set; }
            public string subreddit_id { get; set; }
            public bool author_is_blocked { get; set; }
            public object mod_reason_by { get; set; }
            public object num_reports { get; set; }
            public object removal_reason { get; set; }
            public string link_flair_background_color { get; set; }
            public string id { get; set; }
            public bool is_robot_indexable { get; set; }
            public object report_reasons { get; set; }
            public string author { get; set; }
            public object discussion_type { get; set; }
            public int num_comments { get; set; }
            public bool send_replies { get; set; }
            public string whitelist_status { get; set; }
            public bool contest_mode { get; set; }
            public object[] mod_reports { get; set; }
            public bool author_patreon_flair { get; set; }
            public string author_flair_text_color { get; set; }
            public string permalink { get; set; }
            public string parent_whitelist_status { get; set; }
            public bool stickied { get; set; }
            public string url { get; set; }
            public int subreddit_subscribers { get; set; }
            public float created_utc { get; set; }
            public int num_crossposts { get; set; }
            public Media media { get; set; }
            public bool is_video { get; set; }
            public string url_overridden_by_dest { get; set; }
            public Crosspost_Parent_List[] crosspost_parent_list { get; set; }
            public string crosspost_parent { get; set; }
        }

        public class Media_Embed
        {
            public string content { get; set; }
            public int width { get; set; }
            public bool scrolling { get; set; }
            public int height { get; set; }
        }

        public class Secure_Media
        {
            public string type { get; set; }
            public Oembed oembed { get; set; }
            public Reddit_Video reddit_video { get; set; }
        }

        public class Oembed
        {
            public string provider_url { get; set; }
            public string version { get; set; }
            public string title { get; set; }
            public string type { get; set; }
            public int thumbnail_width { get; set; }
            public int height { get; set; }
            public int width { get; set; }
            public string html { get; set; }
            public string author_name { get; set; }
            public string provider_name { get; set; }
            public string thumbnail_url { get; set; }
            public int thumbnail_height { get; set; }
            public string author_url { get; set; }
        }

        public class Reddit_Video
        {
            public string fallback_url { get; set; }
            public int height { get; set; }
            public int width { get; set; }
            public string scrubber_media_url { get; set; }
            public string dash_url { get; set; }
            public int duration { get; set; }
            public string hls_url { get; set; }
            public bool is_gif { get; set; }
            public string transcoding_status { get; set; }
        }

        public class Secure_Media_Embed
        {
            public string content { get; set; }
            public int width { get; set; }
            public bool scrolling { get; set; }
            public string media_domain_url { get; set; }
            public int height { get; set; }
        }

        public class Gildings
        {
            public int gid_1 { get; set; }
        }

        public class Preview
        {
            public Image[] images { get; set; }
            public bool enabled { get; set; }
        }

        public class Image
        {
            public Source source { get; set; }
            public Resolution[] resolutions { get; set; }
            public Variants variants { get; set; }
            public string id { get; set; }
        }

        public class Source
        {
            public string url { get; set; }
            public int width { get; set; }
            public int height { get; set; }
        }

        public class Variants
        {
        }

        public class Resolution
        {
            public string url { get; set; }
            public int width { get; set; }
            public int height { get; set; }
        }

        public class Media
        {
            public string type { get; set; }
            public Oembed1 oembed { get; set; }
            public Reddit_Video1 reddit_video { get; set; }
        }

        public class Oembed1
        {
            public string provider_url { get; set; }
            public string version { get; set; }
            public string title { get; set; }
            public string type { get; set; }
            public int thumbnail_width { get; set; }
            public int height { get; set; }
            public int width { get; set; }
            public string html { get; set; }
            public string author_name { get; set; }
            public string provider_name { get; set; }
            public string thumbnail_url { get; set; }
            public int thumbnail_height { get; set; }
            public string author_url { get; set; }
        }

        public class Reddit_Video1
        {
            public string fallback_url { get; set; }
            public int height { get; set; }
            public int width { get; set; }
            public string scrubber_media_url { get; set; }
            public string dash_url { get; set; }
            public int duration { get; set; }
            public string hls_url { get; set; }
            public bool is_gif { get; set; }
            public string transcoding_status { get; set; }
        }

        public class Link_Flair_Richtext
        {
            public string e { get; set; }
            public string t { get; set; }
            public string a { get; set; }
            public string u { get; set; }
        }

        public class Author_Flair_Richtext
        {
            public string e { get; set; }
            public string t { get; set; }
            public string a { get; set; }
            public string u { get; set; }
        }

        public class All_Awardings
        {
            public object giver_coin_reward { get; set; }
            public object subreddit_id { get; set; }
            public bool is_new { get; set; }
            public int days_of_drip_extension { get; set; }
            public int coin_price { get; set; }
            public string id { get; set; }
            public object penny_donate { get; set; }
            public string award_sub_type { get; set; }
            public int coin_reward { get; set; }
            public string icon_url { get; set; }
            public int days_of_premium { get; set; }
            public object tiers_by_required_awardings { get; set; }
            public Resized_Icons[] resized_icons { get; set; }
            public int icon_width { get; set; }
            public int static_icon_width { get; set; }
            public object start_date { get; set; }
            public bool is_enabled { get; set; }
            public object awardings_required_to_grant_benefits { get; set; }
            public string description { get; set; }
            public object end_date { get; set; }
            public int subreddit_coin_reward { get; set; }
            public int count { get; set; }
            public int static_icon_height { get; set; }
            public string name { get; set; }
            public Resized_Static_Icons[] resized_static_icons { get; set; }
            public string icon_format { get; set; }
            public int icon_height { get; set; }
            public object penny_price { get; set; }
            public string award_type { get; set; }
            public string static_icon_url { get; set; }
        }

        public class Resized_Icons
        {
            public string url { get; set; }
            public int width { get; set; }
            public int height { get; set; }
        }

        public class Resized_Static_Icons
        {
            public string url { get; set; }
            public int width { get; set; }
            public int height { get; set; }
        }

        public class Crosspost_Parent_List
        {
            public object approved_at_utc { get; set; }
            public string subreddit { get; set; }
            public string selftext { get; set; }
            public string author_fullname { get; set; }
            public bool saved { get; set; }
            public object mod_reason_title { get; set; }
            public int gilded { get; set; }
            public bool clicked { get; set; }
            public string title { get; set; }
            public object[] link_flair_richtext { get; set; }
            public string subreddit_name_prefixed { get; set; }
            public bool hidden { get; set; }
            public int pwls { get; set; }
            public string link_flair_css_class { get; set; }
            public int downs { get; set; }
            public int thumbnail_height { get; set; }
            public object top_awarded_type { get; set; }
            public bool hide_score { get; set; }
            public string name { get; set; }
            public bool quarantine { get; set; }
            public string link_flair_text_color { get; set; }
            public float upvote_ratio { get; set; }
            public object author_flair_background_color { get; set; }
            public string subreddit_type { get; set; }
            public int ups { get; set; }
            public int total_awards_received { get; set; }
            public Media_Embed1 media_embed { get; set; }
            public int thumbnail_width { get; set; }
            public string author_flair_template_id { get; set; }
            public bool is_original_content { get; set; }
            public object[] user_reports { get; set; }
            public Secure_Media1 secure_media { get; set; }
            public bool is_reddit_media_domain { get; set; }
            public bool is_meta { get; set; }
            public object category { get; set; }
            public Secure_Media_Embed1 secure_media_embed { get; set; }
            public string link_flair_text { get; set; }
            public bool can_mod_post { get; set; }
            public int score { get; set; }
            public object approved_by { get; set; }
            public bool is_created_from_ads_ui { get; set; }
            public bool author_premium { get; set; }
            public string thumbnail { get; set; }
            public bool edited { get; set; }
            public object author_flair_css_class { get; set; }
            public object[] author_flair_richtext { get; set; }
            public Gildings1 gildings { get; set; }
            public object content_categories { get; set; }
            public bool is_self { get; set; }
            public object mod_note { get; set; }
            public float created { get; set; }
            public string link_flair_type { get; set; }
            public int wls { get; set; }
            public string removed_by_category { get; set; }
            public object banned_by { get; set; }
            public string author_flair_type { get; set; }
            public string domain { get; set; }
            public bool allow_live_comments { get; set; }
            public object selftext_html { get; set; }
            public bool? likes { get; set; }
            public object suggested_sort { get; set; }
            public object banned_at_utc { get; set; }
            public string url_overridden_by_dest { get; set; }
            public object view_count { get; set; }
            public bool archived { get; set; }
            public bool no_follow { get; set; }
            public bool is_crosspostable { get; set; }
            public bool pinned { get; set; }
            public bool over_18 { get; set; }
            public All_Awardings1[] all_awardings { get; set; }
            public object[] awarders { get; set; }
            public bool media_only { get; set; }
            public string link_flair_template_id { get; set; }
            public bool can_gild { get; set; }
            public bool spoiler { get; set; }
            public bool locked { get; set; }
            public string author_flair_text { get; set; }
            public object[] treatment_tags { get; set; }
            public string rte_mode { get; set; }
            public bool visited { get; set; }
            public object removed_by { get; set; }
            public object num_reports { get; set; }
            public object distinguished { get; set; }
            public string subreddit_id { get; set; }
            public bool author_is_blocked { get; set; }
            public object mod_reason_by { get; set; }
            public object removal_reason { get; set; }
            public string link_flair_background_color { get; set; }
            public string id { get; set; }
            public bool is_robot_indexable { get; set; }
            public object report_reasons { get; set; }
            public string author { get; set; }
            public object discussion_type { get; set; }
            public int num_comments { get; set; }
            public bool send_replies { get; set; }
            public string whitelist_status { get; set; }
            public bool contest_mode { get; set; }
            public object[] mod_reports { get; set; }
            public bool author_patreon_flair { get; set; }
            public string author_flair_text_color { get; set; }
            public string permalink { get; set; }
            public string parent_whitelist_status { get; set; }
            public bool stickied { get; set; }
            public string url { get; set; }
            public int subreddit_subscribers { get; set; }
            public float created_utc { get; set; }
            public int num_crossposts { get; set; }
            public Media1 media { get; set; }
            public bool is_video { get; set; }
            public string post_hint { get; set; }
            public Preview1 preview { get; set; }
        }

        public class Media_Embed1
        {
        }

        public class Secure_Media1
        {
            public Reddit_Video2 reddit_video { get; set; }
        }

        public class Reddit_Video2
        {
            public string fallback_url { get; set; }
            public int height { get; set; }
            public int width { get; set; }
            public string scrubber_media_url { get; set; }
            public string dash_url { get; set; }
            public int duration { get; set; }
            public string hls_url { get; set; }
            public bool is_gif { get; set; }
            public string transcoding_status { get; set; }
        }

        public class Secure_Media_Embed1
        {
        }

        public class Gildings1
        {
            public int gid_1 { get; set; }
        }

        public class Media1
        {
            public Reddit_Video3 reddit_video { get; set; }
        }

        public class Reddit_Video3
        {
            public string fallback_url { get; set; }
            public int height { get; set; }
            public int width { get; set; }
            public string scrubber_media_url { get; set; }
            public string dash_url { get; set; }
            public int duration { get; set; }
            public string hls_url { get; set; }
            public bool is_gif { get; set; }
            public string transcoding_status { get; set; }
        }

        public class Preview1
        {
            public Image1[] images { get; set; }
            public Reddit_Video_Preview reddit_video_preview { get; set; }
            public bool enabled { get; set; }
        }

        public class Reddit_Video_Preview
        {
            public string fallback_url { get; set; }
            public int height { get; set; }
            public int width { get; set; }
            public string scrubber_media_url { get; set; }
            public string dash_url { get; set; }
            public int duration { get; set; }
            public string hls_url { get; set; }
            public bool is_gif { get; set; }
            public string transcoding_status { get; set; }
        }

        public class Image1
        {
            public Source1 source { get; set; }
            public Resolution1[] resolutions { get; set; }
            public Variants1 variants { get; set; }
            public string id { get; set; }
        }

        public class Source1
        {
            public string url { get; set; }
            public int width { get; set; }
            public int height { get; set; }
        }

        public class Variants1
        {
        }

        public class Resolution1
        {
            public string url { get; set; }
            public int width { get; set; }
            public int height { get; set; }
        }

        public class All_Awardings1
        {
            public int? giver_coin_reward { get; set; }
            public object subreddit_id { get; set; }
            public bool is_new { get; set; }
            public int days_of_drip_extension { get; set; }
            public int coin_price { get; set; }
            public string id { get; set; }
            public int? penny_donate { get; set; }
            public string award_sub_type { get; set; }
            public int coin_reward { get; set; }
            public string icon_url { get; set; }
            public int days_of_premium { get; set; }
            public object tiers_by_required_awardings { get; set; }
            public Resized_Icons1[] resized_icons { get; set; }
            public int icon_width { get; set; }
            public int static_icon_width { get; set; }
            public object start_date { get; set; }
            public bool is_enabled { get; set; }
            public object awardings_required_to_grant_benefits { get; set; }
            public string description { get; set; }
            public object end_date { get; set; }
            public int subreddit_coin_reward { get; set; }
            public int count { get; set; }
            public int static_icon_height { get; set; }
            public string name { get; set; }
            public Resized_Static_Icons1[] resized_static_icons { get; set; }
            public string icon_format { get; set; }
            public int icon_height { get; set; }
            public int? penny_price { get; set; }
            public string award_type { get; set; }
            public string static_icon_url { get; set; }
        }

        public class Resized_Icons1
        {
            public string url { get; set; }
            public int width { get; set; }
            public int height { get; set; }
        }

        public class Resized_Static_Icons1
        {
            public string url { get; set; }
            public int width { get; set; }
            public int height { get; set; }
        }
    }
#pragma warning restore IDE1006 // Naming Styles
}
