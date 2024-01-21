using Pastel;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text.Json;

namespace Reecon
{
    class OSINT_Instagram
    {
        public static InstagramInfo GetInfo(string username)
        {
            InstagramInfo instagramInfo = new InstagramInfo();
            string pageText = Web.DownloadString($"https://www.instagram.com/web/search/topsearch/?query={username}", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36").Text;
            // 
            OSINT_Instagram_Info.Rootobject theObject = (OSINT_Instagram_Info.Rootobject)JsonSerializer.Deserialize(pageText, typeof(OSINT_Instagram_Info.Rootobject), SourceGenerationContext.Default);
            if (theObject.users == null || theObject.users.Length == 0)
            {
                Console.WriteLine("- Instagram: Not Found");
            }
            else
            {
                Console.WriteLine("- Instagram: " + "Found".Pastel(Color.Green));
                foreach (OSINT_Instagram_Info.User user in theObject.users)
                {
                    string userUsername = user.user.username;
                    if (userUsername == username || userUsername == username.ToLower())
                    {
                        instagramInfo.Exists = true;
                        instagramInfo.Users.Add(user);

                    }
                }
            }
            return instagramInfo;
        }
    }

    public class InstagramInfo
    {
        public bool Exists = false;
        public List<OSINT_Instagram_Info.User> Users = new List<OSINT_Instagram_Info.User>();
    }

    // Pasted as JSON from https://www.instagram.com/web/search/topsearch/?query=Reelix
    public class OSINT_Instagram_Info
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
}
