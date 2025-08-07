using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text.Json;

namespace Reecon
{
    class Osint_Instagram
    {
        public static InstagramInfo GetInfo(string username)
        {
            InstagramInfo instagramInfo = new InstagramInfo();
            /*
            string pageText = Web.DownloadString($"https://www.instagram.com/web/search/topsearch/?query={username}", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36").Text;
            // 
            OSINT_Instagram_Info.Rootobject theObject = (OSINT_Instagram_Info.Rootobject)JsonSerializer.Deserialize(pageText, typeof(OSINT_Instagram_Info.Rootobject));
            if (theObject.users == null || theObject.users.Length == 0)
            {
                Console.WriteLine("- Instagram: Not Found");
            }
            else
            {
                Console.WriteLine("- Instagram: " + "Found".Recolor(Color.Green));
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
            */
            return instagramInfo;
        }
    }

    public class InstagramInfo
    {
        public bool Exists = false;
        public List<OSINT_Instagram_Info> Users = new List<OSINT_Instagram_Info>();
    }

    // Pasted as JSON from https://www.instagram.com/web/search/topsearch/?query=Reelix
    public class OSINT_Instagram_Info
    {
        // No longer works
    }
}
