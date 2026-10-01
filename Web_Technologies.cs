using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Reecon.Color;

namespace Reecon;

public class Web_Technologies
{
    private static readonly List<string> DetectedTechnologies = [];

    // Drupal
    public string DrupalChecks(string? pageText, string urlWithSlash)
    {
        if (DetectedTechnologies.Contains("Drupal"))
        {
            return "";
        }
        DetectedTechnologies.Add("Drupal");
        
        string toReturn = "- Drupal detected".Recolor(Recolor.Orange) + Environment.NewLine;
        // TODO: Do these in-code
        toReturn += $"-- Possible Version Detection: curl -s {urlWithSlash}CHANGELOG.txt | grep -m2 \"\"" + Environment.NewLine;
        // Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1
        // Drupalgeddon - https://nvd.nist.gov/vuln/detail/cve-2018-7600
        // 1, 2, 3 o_O
        toReturn += $"-- Possible Version Detection 2: curl -s {urlWithSlash} grep 'content=\"Drupal'" + Environment.NewLine;
        toReturn += $"-- Content Discovery: {urlWithSlash}node/1 (2,3,4,etc.)" + Environment.NewLine;
        toReturn += $"--- Run: droopescan scan drupal -u {urlWithSlash} (pipx install droopescan)" + Environment.NewLine;
        return toReturn;
    }
    
    // Next.js
    public string NextJsChecks(string? pageText, string urlWithSlash)
    {
        if (DetectedTechnologies.Contains("Next.js"))
        {
            return "";
        }
        DetectedTechnologies.Add("Next.js");
        
        string toReturn = "- Next.js detected".Recolor(Recolor.Orange) + Environment.NewLine;
        
        // JS: log(window.next.version)
        if (pageText != null)
        {
            // /_next/static/chunks/*.js
            // Also preventing *.json / *.js.map
            var chunkRegex = new Regex(
                @"/?_next/static/chunks/[^\s""'<>]+\.js(?:\?[^\s""'<>]*)?", 
                RegexOptions.IgnoreCase | RegexOptions.Compiled
            );
            
            // Get all the unique ones
            List<string> jsChunks = chunkRegex.Matches(pageText)
                .Select(m => m.Value)
                .Distinct()
                .ToList();

            // Go through each, download them, and search for the version
            foreach (string jsChunk in jsChunks)
            {
                var jsDownload = Web.DownloadString($"{urlWithSlash}{jsChunk}");
                if (jsDownload.StatusCode == HttpStatusCode.OK)
                {
                    string jsString = jsDownload.Text;
                    if (jsString.Contains("window.next={version:\""))
                    {
                        string version = jsString.Remove(0, jsString.IndexOf("window.next={version:\"", StringComparison.Ordinal) + 22);
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
                            toReturn += "--- " + "Vulnerable to React2Shell (CVE-2025-55182) - https://raw.githubusercontent.com/xalgord/React2Shell/refs/heads/master/react2shell.py".Recolor(Recolor.Red) + Environment.NewLine;
                            toReturn += "---- " + $"python3 react2shell.py -u {urlWithSlash}".Recolor(Recolor.Red) + Environment.NewLine;
                        }
                        else
                        {
                            toReturn += "--- Not vulnerable to React2Shell (CVE-2025-55182) :<" + Environment.NewLine;
                        }
                        
                        // CVE-2026-94545
                        // site.com/api/og
                        // Vulnerable	Next.js 16.2.0 – 16.3.5 (Node runtime, sharp present), Satori >=0.0.27 <0.33.5
                        // Patched	Next.js 16.3.6 / Satori 0.33.5 or later
                        if (
                            theVersion >= Version.Parse("16.2.0") && theVersion <= Version.Parse("16.3.5")
                        )
                        {
                            toReturn += "--- " + "Vulnerable to CVE-2026-94545 - Check if /api/og exists, then Check https://github.com/EQSTLab/CVE-2026-94545".Recolor(Recolor.Red) + Environment.NewLine;
                        }

                        break;
                    }
                }
            }
        }
        return toReturn;
    }
    
    // Roundcube
    public string RoundcubeChecks(string? pageText, string urlWithSlash)
    {
        if (DetectedTechnologies.Contains("Roundcube"))
        {
            return "";
        }
        DetectedTechnologies.Add("Roundcube");
        
        string toReturn = "- " + $"Roundcube detected".Recolor(Recolor.Orange) + Environment.NewLine;
        if (pageText != null && pageText.Contains("rcmail.set_env"))
        {
            string rcMailVars = pageText.Remove(0, pageText.IndexOf("rcmail.set_env", StringComparison.Ordinal));
            rcMailVars = rcMailVars.Substring(0, rcMailVars.IndexOf("</script>", StringComparison.Ordinal));
            if (rcMailVars.Contains("rcversion"))
            {
                string rcMailVersion = rcMailVars.Remove(0,  rcMailVars.IndexOf("rcversion", StringComparison.Ordinal) + 11);
                rcMailVersion = rcMailVersion.Substring(0, rcMailVersion.IndexOf(','));
                // Roundcube uses an integer format for versions: Major * 10000 + Minor * 100 + Patch.
                int rcVersion = int.Parse(rcMailVersion);
                int major = rcVersion / 10000;
                int minor = (rcVersion % 10000) / 100;
                int patch = rcVersion % 100;
                string rcMailVersionText = $"{major}.{minor}.{patch}";
                toReturn += "-- " + $"Version: {rcMailVersionText}".Recolor(Recolor.Orange) + Environment.NewLine;
                // https://nvd.nist.gov/vuln/detail/cve-2026-48842
                // Roundcube Webmail 1.6.x before 1.6.16 and 1.7.x before 1.7.1
                Version version = Version.Parse(rcMailVersionText);
                if ((version >= Version.Parse("1.6") && version < Version.Parse("1.6.16")) ||
                    (version >= Version.Parse("1.7") && version < Version.Parse("1.7.2")))
                {
                    toReturn += "--- " + "Vulnerable to CVE-2026-48842 (https://nvd.nist.gov/vuln/detail/cve-2026-48842)".Recolor(Recolor.Orange) + Environment.NewLine;
                    toReturn += "--- " + "Download: https://raw.githubusercontent.com/GODofExploit/exploit-arsenal/main/web-application/CVE-2026-48842/CVE-2026-48842.py".Recolor(Recolor.Orange) + Environment.NewLine;
                }
            }
        }

        return toReturn;
    }
}