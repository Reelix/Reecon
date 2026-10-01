using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using Reecon.Color;

namespace Reecon
{
    internal static class Nist
    {
        public static void Search(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Search Usage: reecon -search Program Name Here");
                return;
            }
            string programName = string.Join('+', args.Skip(1)).Trim();
            Console.WriteLine($"Searching for CVE's for {programName}...");
            string URL = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={programName}&resultsPerPage=250";
            Web.HttpInfo jsonPage = Web.GetHttpInfo(URL, "Reecon (https://github.com/Reelix/reecon)", Timeout: 15);
            if (jsonPage.StatusCode == HttpStatusCode.OK && jsonPage.PageText != null)
            {
                // Use JsonDocument instead of generated context
                using JsonDocument document = JsonDocument.Parse(jsonPage.PageText);
                JsonElement root = document.RootElement;

                if (!root.TryGetProperty("vulnerabilities", out JsonElement vulnsArray))
                {
                    Console.WriteLine("Nist.cs - Some Weird Error :(");
                    return;
                }

                List<JsonElement> highVulns = [];
                foreach (JsonElement vuln in vulnsArray.EnumerateArray())
                {
                    JsonElement cve = vuln.GetProperty("cve");
                    float baseScore = 0f;

                    if (cve.TryGetProperty("metrics", out JsonElement metrics))
                    {
                        var v31Match = GetFirstHighScore(metrics, "cvssMetricV31");
                        var v40Match = GetFirstHighScore(metrics, "cvssMetricV40");
                        var v30Match = GetFirstHighScore(metrics, "cvssMetricV30");

                        if (v31Match != null) baseScore = v31Match.Value;
                        else if (v40Match != null) baseScore = v40Match.Value;
                        else if (v30Match != null) baseScore = v30Match.Value;
                    }

                    if (baseScore >= 6f)
                        highVulns.Add(vuln);
                }

                // Sort by ID descending (latest first)
                highVulns.Sort((a, b) => string.Compare(
                    a.GetProperty("cve").GetProperty("id").GetString() ?? "",
                    b.GetProperty("cve").GetProperty("id").GetString() ?? "",
                    StringComparison.Ordinal));
                highVulns.Reverse();

                if (highVulns.Count > 0)
                {
                    foreach (JsonElement vuln in highVulns)
                    {
                        JsonElement cve = vuln.GetProperty("cve");
                        string cveId = cve.GetProperty("id").GetString() ?? "";
                        float baseScore = 0.0f;

                        // Get some data - Priority goes 3.1 -> 4.0 -> 3.0 (Personal preference)
                        // This is a bit cumbersome, but it works

                        JsonElement metrics = cve.GetProperty("metrics");
                        var v31Match = GetFirstHighScore(metrics, "cvssMetricV31");
                        var v40Match = GetFirstHighScore(metrics, "cvssMetricV40");
                        var v30Match = GetFirstHighScore(metrics, "cvssMetricV30");

                        if (v31Match != null)
                        {
                            baseScore = v31Match.Value;
                        }
                        else if (v40Match != null)
                        {
                            baseScore = v40Match.Value;
                        }
                        else if (v30Match != null)
                        {
                            baseScore = v30Match.Value;
                        }

                        Console.WriteLine(cveId.Recolor(Recolor.Green));
                        Console.WriteLine($"- Link: https://nvd.nist.gov/vuln/detail/{cveId}");
                        Console.WriteLine($"- Score: {(baseScore >= 8.0f ? $"{baseScore}".Recolor(Recolor.Red) : baseScore)}");

                        string description = "";
                        JsonElement descriptions = cve.GetProperty("descriptions");
                        foreach (JsonElement desc in descriptions.EnumerateArray())
                        {
                            if (desc.GetProperty("lang").GetString() == "en")
                            {
                                description = desc.GetProperty("value").GetString()?.Trim() ?? "";
                                break;
                            }
                        }
                        Console.WriteLine($"- Desc: {description}");

                        if (cve.TryGetProperty("configurations", out JsonElement configs))
                        {
                            foreach (JsonElement config in configs.EnumerateArray())
                            {
                                JsonElement nodes = config.GetProperty("nodes");
                                foreach (JsonElement node in nodes.EnumerateArray())
                                {
                                    JsonElement cpeMatches = node.GetProperty("cpeMatch");
                                    foreach (JsonElement cpeMatch in cpeMatches.EnumerateArray())
                                    {
                                        string criteria = cpeMatch.GetProperty("criteria").GetString() ?? "Unknown - Bug Reelix";
                                        criteria = criteria.Replace("cpe:2.3:a:", "");
                                        criteria = criteria.Replace(":*", "");

                                        if (cveId == "CVE-2021-41267")
                                        {
                                            Console.WriteLine("Breakpoint");
                                        }
                                        string? versionStartIncluding = cpeMatch.TryGetProperty("versionStartIncluding", out JsonElement vsi) ? vsi.GetString() : null;
                                        string? versionEndIncluding = cpeMatch.TryGetProperty("versionEndIncluding", out JsonElement vei) ? vei.GetString() : null;
                                        string? versionEndExcluding = cpeMatch.TryGetProperty("versionEndExcluding", out JsonElement vee) ? vee.GetString() : null;

                                        string affected = "";
                                        if (versionStartIncluding != null && versionEndIncluding == null && versionEndExcluding == null)
                                        {
                                            affected = $"All versions since {versionStartIncluding} (Including)";
                                        }
                                        else if (versionStartIncluding == null && versionEndIncluding == null && versionEndExcluding != null)
                                        {
                                            affected = "All versions before " + versionEndExcluding;
                                        }
                                        else if (versionStartIncluding == null && versionEndIncluding != null && versionEndExcluding == null)
                                        {
                                            affected = "All versions up to, and including " + versionEndIncluding;
                                        }
                                        else if (versionStartIncluding != null && versionEndIncluding != null && versionEndExcluding == null)
                                        {
                                            affected = $"From {versionStartIncluding} to {versionEndIncluding} (Including)";
                                        }
                                        else if (versionStartIncluding != null && versionEndIncluding == null && versionEndExcluding != null)
                                        {
                                            affected = $"From {versionStartIncluding} to {versionEndExcluding} (Excluding)";
                                        }
                                        else if (versionStartIncluding == null && versionEndIncluding == null && versionEndExcluding == null)
                                        {
                                            affected = "All"; // Is it, or is it just not stated?
                                        }
                                        else
                                        {
                                            Console.WriteLine("Woof");
                                        }

                                        Console.WriteLine($"- Affected Version: {criteria}{(affected != "" ? $" ({affected})" : "")}");
                                    }
                                }
                            }
                        }

                        JsonElement references = cve.GetProperty("references");
                        foreach (JsonElement reference in references.EnumerateArray())
                        {
                            if (reference.TryGetProperty("tags", out JsonElement tagsEl))
                            {
                                List<string> tags = [];
                                foreach (JsonElement tag in tagsEl.EnumerateArray())
                                    tags.Add(tag.GetString() ?? "");

                                string tagsStr = string.Join(',', tags);
                                string? url = reference.GetProperty("url").GetString();
                                string? source = reference.GetProperty("source").GetString();

                                if (tags.Contains("Exploit"))
                                {
                                    Console.WriteLine("- Ref: " +
                                                      $"{url} - {source}".Recolor(Recolor.Red) +
                                                      $" ({tagsStr})");
                                }
                                else
                                {
                                    Console.WriteLine($"- Ref: {url} - {source} ({tagsStr})");
                                }
                            }
                        }
                        Console.WriteLine();
                    }
                }
                else
                {
                    Console.WriteLine($"0 relevant results found for {programName}");
                }
            }
            else
            {
                Console.WriteLine($"Error with: {URL}" + Environment.NewLine + "- Nist returned: " + jsonPage.StatusCode);
            }
        }

        
        private static float? GetFirstHighScore(JsonElement metrics, string key)
        {
            if (!metrics.TryGetProperty(key, out JsonElement arr)) return null;
            foreach (JsonElement metric in arr.EnumerateArray())
            {
                if (metric.TryGetProperty("cvssData", out JsonElement cvss) &&
                    cvss.TryGetProperty("baseScore", out JsonElement score))
                {
                    float s = score.GetSingle();
                    if (s >= 6f) return s;
                }
            }
            return null;
        }
    }
}