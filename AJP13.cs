using Pastel;
using System.Drawing;

namespace Reecon
{
    class AJP13 // 8009 - Just AJP?
    {
        public static string GetInfo(string target, int port)
        {
            if (CheckGhostcat(target))
            {
                return "-- Vulnerable to CVE-2020-1938!".Pastel(Color.Orange);
            }
            else
            {
                return "-- No useful info :<";
            }
        }

        private static bool CheckGhostcat(string target)
        {
            var httpInfo = Web.GetHTTPInfo($"http://{target}/");
            if (httpInfo.StatusCode == 0)
            {
                httpInfo = Web.GetHTTPInfo($"http://{target}:8080/");
                if (httpInfo.StatusCode == 0)
                {
                    return false;
                }
            }
            string pageTitle = httpInfo.PageTitle;
            // Apache Tomcat/9.0.30
            if (!pageTitle.StartsWith("Apache Tomcat/"))
            {
                return false;
            }
            pageTitle = pageTitle.Replace("Apache Tomcat/", "");
            System.Version theVersion = System.Version.Parse(pageTitle);

            // In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99,
            
            // 6.* is EOL and unpatched
            if (theVersion.Major <= 6)
            {
                return true;
            }
            // Below 7.0.100
            if (theVersion.Major == 7 && theVersion < System.Version.Parse("7.0.100"))
            {
                return true;
            }
            // Below 8.5.51
            else if (theVersion.Major == 8 && theVersion < System.Version.Parse("8.5.51"))
            {
                return true;
            }
            // Below 9.0.31
            else if (theVersion.Major == 9 && theVersion < System.Version.Parse("9.0.31"))
            {
                return true;
            }
            return false;
        }
    }
}
