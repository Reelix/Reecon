using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;

namespace Reecon;

public class Web_Technologies
{
    public static string NextJSChecks(string pageText, string urlWithSlash)
    {
        string toReturn = "- Next.js detected" + Environment.NewLine;
        // JS: log(window.next.version)
        if (pageText != null)
        {
            List<string> chunks = pageText.Split(new[] { "/_next/static/chunks/" }, StringSplitOptions.RemoveEmptyEntries).ToList();

            // Only keep the JS ones
            chunks = chunks.Where(x => x.Contains(".js\"")).ToList();

            // Go through each, download them, and search for the version
            foreach (string chunk in chunks)
            {
                string jsPath = chunk.Substring(0, chunk.IndexOf('"'));
                var jsDownload = Web.DownloadString($"{urlWithSlash}_next/static/chunks/{jsPath}");
                if (jsDownload.StatusCode == HttpStatusCode.OK)
                {
                    string jsString = jsDownload.Text;
                    if (jsString.Contains("window.next={version:\""))
                    {
                        string version = jsString.Remove(0, jsString.IndexOf("window.next={version:\"") + 22);
                        version = version.Substring(0, version.IndexOf('"'));
                        toReturn += $@"-- Version: {version}" + Environment.NewLine;

                        // https://www.dynatrace.com/news/blog/cve-2025-55182-react2shell-critical-vulnerability-what-it-is-and-what-to-do/
                        /* Upgrade Next.js to one of the following versions, or higher:

                           15.0.5
                           15.1.9
                           15.2.6
                           15.3.6
                           15.4.8
                           15.5.7
                           16.0.7
                         */
                        Version theVersion = Version.Parse(version);
                        if (
                            theVersion >= Version.Parse("15.0.0") && theVersion < Version.Parse("15.0.5") ||
                            theVersion >= Version.Parse("15.1.0") && theVersion < Version.Parse("15.1.9") ||
                            theVersion >= Version.Parse("15.2.0") && theVersion < Version.Parse("15.2.6") ||
                            theVersion >= Version.Parse("15.3.0") && theVersion < Version.Parse("15.3.6") ||
                            theVersion >= Version.Parse("15.4.0") && theVersion < Version.Parse("15.4.8") ||
                            theVersion >= Version.Parse("15.5.0") && theVersion < Version.Parse("15.5.7") ||
                            theVersion >= Version.Parse("16.0.0") && theVersion < Version.Parse("16.0.7")
                        )
                        {
                            toReturn += "--- " + "Vulnerable to React2Shell (CVE-2025-55182) - https://raw.githubusercontent.com/xalgord/React2Shell/refs/heads/master/react2shell.py".Recolor(Color.Red) + Environment.NewLine;
                            toReturn += "---- " + $"python3 react2shell.py -u {urlWithSlash}".Recolor(Color.Red) + Environment.NewLine;
                        }
                        else
                        {
                            toReturn += "--- Not vulnerable to React2Shell (CVE-2025-55182) :<" + Environment.NewLine;
                        }

                        break;
                    }
                }
            }
        }
        return toReturn;
    }
}