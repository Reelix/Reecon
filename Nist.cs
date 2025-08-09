using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

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
                // Use the generated context for deserialization
                Rootobject? myObject = JsonSerializer.Deserialize(jsonPage.PageText, NistJsonContext.Default.Rootobject);
                if (myObject == null)
                {
                    Console.WriteLine("Nist.cs - Some Weird Error :(");
                    return;
                }

                List<Vulnerability> highVulns = myObject.vulnerabilities.Where(x =>
                    (x.cve.metrics.cvssMetricV31 != null && x.cve.metrics.cvssMetricV31.Any(y => y.cvssData.baseScore >= 6f)) ||
                    (x.cve.metrics.cvssMetricV40 != null && x.cve.metrics.cvssMetricV40.Any(y => y.cvssData.baseScore >= 6f))
                ).ToList();

                highVulns = highVulns.OrderByDescending(x => x.cve.id).ToList();
                if (highVulns.Count > 0)
                {
                    foreach (Vulnerability vuln in highVulns)
                    {
                        Cve cve = vuln.cve;
                        Console.WriteLine(cve.id.Recolor(Color.Green));
                        Console.WriteLine($"- Link: https://nvd.nist.gov/vuln/detail/{cve.id}");
                        string description = cve.descriptions.First(x => x.lang == "en").value;
                        Console.WriteLine("- Desc: " + description.Trim());

                        if (cve.configurations != null)
                        {
                            foreach (Configuration config in cve.configurations)
                            {
                                foreach (Node node in config.nodes)
                                {
                                    foreach (Cpematch cpeMatch in node.cpeMatch)
                                    {
                                        string criteria = cpeMatch.criteria;
                                        criteria = criteria.Replace("cpe:2.3:a:", "");
                                        criteria = criteria.Replace(":*", "");

                                        string? versionStartIncluding = cpeMatch.versionStartIncluding;
                                        string? versionEndIncluding = cpeMatch.versionEndIncluding;
                                        string? versionEndExcluding = cpeMatch.versionEndExcluding;

                                        string affected = "";
                                        if (versionStartIncluding == null && versionEndIncluding == null && versionEndExcluding != null)
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
                                            affected = $"From {versionStartIncluding} to {versionEndIncluding} (Excluding)";
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

                        foreach (Reference reference in cve.references)
                        {
                            if (reference.tags != null)
                            {
                                string tags = string.Join(',', reference.tags);
                                if (reference.tags.Contains("Exploit"))
                                {
                                    Console.WriteLine("- Ref: " +
                                                      $"{reference.url} - {reference.source}".Recolor(Color.Red) +
                                                      $" ({tags})");
                                }
                                else
                                {
                                    Console.WriteLine($"- Ref: {reference.url} - {reference.source} ({tags})");
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
    }

    // Define the JSON context with source generation
    [JsonSourceGenerationOptions(WriteIndented = true)]
    [JsonSerializable(typeof(Rootobject))]
    [JsonSerializable(typeof(Vulnerability))]
    [JsonSerializable(typeof(Cve))]
    [JsonSerializable(typeof(Metrics))]
    [JsonSerializable(typeof(Cvssmetricv2))]
    [JsonSerializable(typeof(Cvssdata))]
    [JsonSerializable(typeof(Cvssmetricv31))]
    [JsonSerializable(typeof(Cvssdata1))]
    [JsonSerializable(typeof(Cvssmetricv30))]
    [JsonSerializable(typeof(Cvssdata2))]
    [JsonSerializable(typeof(Cvssmetricv40))]
    [JsonSerializable(typeof(Cvssdata3))]
    [JsonSerializable(typeof(Description))]
    [JsonSerializable(typeof(Weakness))]
    [JsonSerializable(typeof(Description1))]
    [JsonSerializable(typeof(Configuration))]
    [JsonSerializable(typeof(Node))]
    [JsonSerializable(typeof(Cpematch))]
    [JsonSerializable(typeof(Reference))]
    public partial class NistJsonContext : JsonSerializerContext
    {

    }

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
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
        public Configuration[]? configurations { get; set; }
        public Reference[] references { get; set; }
        public string evaluatorComment { get; set; }
    }

    public class Metrics
    {
        public Cvssmetricv2[]? cvssMetricV2 { get; set; }
        public Cvssmetricv31[]? cvssMetricV31 { get; set; }
        public Cvssmetricv30[]? cvssMetricV30 { get; set; }
        public Cvssmetricv40[]? cvssMetricV40 { get; set; }
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

    public class Cvssmetricv40
    {
        public string source { get; set; }
        public string type { get; set; }
        public Cvssdata3 cvssData { get; set; }
    }

    public class Cvssdata3
    {
        public string version { get; set; }
        public string vectorString { get; set; }
        public float baseScore { get; set; }
        public string baseSeverity { get; set; }
        public string attackVector { get; set; }
        public string attackComplexity { get; set; }
        public string attackRequirements { get; set; }
        public string privilegesRequired { get; set; }
        public string userInteraction { get; set; }
        public string vulnerableSystemConfidentiality { get; set; }
        public string vulnerableSystemIntegrity { get; set; }
        public string vulnerableSystemAvailability { get; set; }
        public string subsequentSystemConfidentiality { get; set; }
        public string subsequentSystemIntegrity { get; set; }
        public string subsequentSystemAvailability { get; set; }
        public string exploitMaturity { get; set; }
        public string confidentialityRequirements { get; set; }
        public string integrityRequirements { get; set; }
        public string availabilityRequirements { get; set; }
        public string modifiedAttackVector { get; set; }
        public string modifiedAttackComplexity { get; set; }
        public string modifiedAttackRequirements { get; set; }
        public string modifiedPrivilegesRequired { get; set; }
        public string modifiedUserInteraction { get; set; }
        public string modifiedVulnerableSystemConfidentiality { get; set; }
        public string modifiedVulnerableSystemIntegrity { get; set; }
        public string modifiedVulnerableSystemAvailability { get; set; }
        public string modifiedSubsequentSystemConfidentiality { get; set; }
        public string modifiedSubsequentSystemIntegrity { get; set; }
        public string modifiedSubsequentSystemAvailability { get; set; }
        public string safety { get; set; }
        public string automatable { get; set; }
        public string recovery { get; set; }
        public string valueDensity { get; set; }
        public string vulnerabilityResponseEffort { get; set; }
        public string providerUrgency { get; set; }
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
        [JsonPropertyName("operator")]
        public string _operator { get; set; }
        public bool negate { get; set; }
        public Cpematch[] cpeMatch { get; set; }
    }

    public class Cpematch
    {
        public bool vulnerable { get; set; }
        public string criteria { get; set; }
        public string? versionEndIncluding { get; set; }
        public string matchCriteriaId { get; set; }
        public string? versionEndExcluding { get; set; }
        public string? versionStartIncluding { get; set; }
    }

    public class Reference
    {
        public string url { get; set; }
        public string source { get; set; }
        public string[]? tags { get; set; }
    }
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
}