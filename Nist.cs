﻿using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text.Json;

namespace Reecon
{
    class Nist
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
            var jsonPage = Web.GetHTTPInfo(URL, "Reecon (https://github.com/Reelix/reecon)");
            if (jsonPage.StatusCode == HttpStatusCode.OK)
            {
                Rootobject myObject = JsonSerializer.Deserialize<Rootobject>(jsonPage.PageText);
                List <Vulnerability> highVulns = myObject.vulnerabilities.Where(x => x.cve.metrics.cvssMetricV31 != null && x.cve.metrics.cvssMetricV31.Any(x => x.cvssData.baseScore >= 6f)).ToList();
                highVulns = highVulns.OrderByDescending(x => x.cve.id).ToList();
                if (highVulns.Count > 0)
                {
                    foreach (var vuln in highVulns)
                    {
                        Cve cve = vuln.cve;
                        Console.WriteLine(cve.id.Recolor(Color.Green));
                        Console.WriteLine($"- Link: https://nvd.nist.gov/vuln/detail/{cve.id}");
                        string description = cve.descriptions.Where(x => x.lang == "en").FirstOrDefault().value;
                        Console.WriteLine("- Desc: " + description.Trim());

                        // Probably a cleaner way to do this, but hey
                        foreach (Reference reference in cve.references)
                        {
                            string tags = "";
                            if (reference.tags != null)
                            {
                                tags = string.Join(',', reference.tags);
                                if (reference.tags.Contains("Exploit"))
                                {
                                    Console.WriteLine("- Ref: " + $"{reference.url} - {reference.source}".Recolor(Color.Red) + $" ({tags})");
                                }
                                else
                                {
                                    Console.WriteLine($"- Ref: {reference.url} - {reference.source} ({tags})");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"- Ref: {reference.url} - {reference.source}");
                            }
                        }

                        // Leave an empty gap between each CVE
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
    }

    public class Rootobject
    {
        public int resultsPerPage { get; set; }
        public int startIndex { get; set; }
        public int totalResults { get; set; }
        public string format { get; set; }
        public string version { get; set; }
        public DateTime timestamp { get; set; }
        public Vulnerability[] vulnerabilities { get; set; }
    }

    public class Vulnerability
    {
        public Cve cve { get; set; }
    }

    public class Cve
    {
        public string id { get; set; }
        public string sourceIdentifier { get; set; }
        public DateTime published { get; set; }
        public DateTime lastModified { get; set; }
        public string vulnStatus { get; set; }
        public object[] cveTags { get; set; }
        public Description[] descriptions { get; set; }
        public Metrics metrics { get; set; }
        public Weakness[] weaknesses { get; set; }
        public Configuration[] configurations { get; set; }
        public Reference[] references { get; set; }
        public string evaluatorComment { get; set; }
    }

    public class Metrics
    {
        public Cvssmetricv2[] cvssMetricV2 { get; set; }
        public Cvssmetricv31[] cvssMetricV31 { get; set; }
        public Cvssmetricv30[] cvssMetricV30 { get; set; }
    }

    public class Cvssmetricv2
    {
        public string source { get; set; }
        public string type { get; set; }
        public Cvssdata cvssData { get; set; }
        public string baseSeverity { get; set; }
        public float exploitabilityScore { get; set; }
        public float impactScore { get; set; }
        public bool acInsufInfo { get; set; }
        public bool obtainAllPrivilege { get; set; }
        public bool obtainUserPrivilege { get; set; }
        public bool obtainOtherPrivilege { get; set; }
        public bool userInteractionRequired { get; set; }
    }

    public class Cvssdata
    {
        public string version { get; set; }
        public string vectorString { get; set; }
        public string accessVector { get; set; }
        public string accessComplexity { get; set; }
        public string authentication { get; set; }
        public string confidentialityImpact { get; set; }
        public string integrityImpact { get; set; }
        public string availabilityImpact { get; set; }
        public float baseScore { get; set; }
    }

    public class Cvssmetricv31
    {
        public string source { get; set; }
        public string type { get; set; }
        public Cvssdata1 cvssData { get; set; }
        public float exploitabilityScore { get; set; }
        public float impactScore { get; set; }
    }

    public class Cvssdata1
    {
        public string version { get; set; }
        public string vectorString { get; set; }
        public string attackVector { get; set; }
        public string attackComplexity { get; set; }
        public string privilegesRequired { get; set; }
        public string userInteraction { get; set; }
        public string scope { get; set; }
        public string confidentialityImpact { get; set; }
        public string integrityImpact { get; set; }
        public string availabilityImpact { get; set; }
        public float baseScore { get; set; }
        public string baseSeverity { get; set; }
    }

    public class Cvssmetricv30
    {
        public string source { get; set; }
        public string type { get; set; }
        public Cvssdata2 cvssData { get; set; }
        public float exploitabilityScore { get; set; }
        public float impactScore { get; set; }
    }

    public class Cvssdata2
    {
        public string version { get; set; }
        public string vectorString { get; set; }
        public string attackVector { get; set; }
        public string attackComplexity { get; set; }
        public string privilegesRequired { get; set; }
        public string userInteraction { get; set; }
        public string scope { get; set; }
        public string confidentialityImpact { get; set; }
        public string integrityImpact { get; set; }
        public string availabilityImpact { get; set; }
        public float baseScore { get; set; }
        public string baseSeverity { get; set; }
    }

    public class Description
    {
        public string lang { get; set; }
        public string value { get; set; }
    }

    public class Weakness
    {
        public string source { get; set; }
        public string type { get; set; }
        public Description1[] description { get; set; }
    }

    public class Description1
    {
        public string lang { get; set; }
        public string value { get; set; }
    }

    public class Configuration
    {
        public Node[] nodes { get; set; }
    }

    public class Node
    {
        public string _operator { get; set; }
        public bool negate { get; set; }
        public Cpematch[] cpeMatch { get; set; }
    }

    public class Cpematch
    {
        public bool vulnerable { get; set; }
        public string criteria { get; set; }
        public string versionEndIncluding { get; set; }
        public string matchCriteriaId { get; set; }
        public string versionEndExcluding { get; set; }
        public string versionStartIncluding { get; set; }
    }

    public class Reference
    {
        public string url { get; set; }
        public string source { get; set; }
        public string[] tags { get; set; }
    }

}
