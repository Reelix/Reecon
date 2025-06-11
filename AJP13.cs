using System.Drawing;

namespace Reecon
{
    class AJP13 // 8009 - Just AJP?
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            // https://nvd.nist.gov/vuln/detail/cve-2020-1938
            // https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938
            if (CheckGhostcat(target))
            {
                return ("AFJP13", "-- Vulnerable to CVE-2020-1938!".Recolor(Color.Orange));
            }
            else
            {
                return ("AJP13", "-- No useful info :<");
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
            string? pageTitle = httpInfo.PageTitle;
            // Apache Tomcat/9.0.30
            if (pageTitle != null && !pageTitle.StartsWith("Apache Tomcat/"))
            {
                return false;
            }
            pageTitle = pageTitle?.Replace("Apache Tomcat/", "");
            System.Version theVersion = System.Version.Parse(pageTitle);


            // In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99,
            // 6.* is EOL and unpatched

            // Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later.\

            // 9.0.31 or 9.0.0.31??
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
