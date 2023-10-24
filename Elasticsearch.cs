using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;


namespace Reecon
{
    class Elasticsearch // Port 9200
    {
        public static string GetInfo(string ip, int port)
        {
            string returnString = "";
            // Get basic data
            string pageData = Web.DownloadString($"http://{ip}:{port}/");
            ElasticSearchObject theObject = JsonSerializer.Deserialize<ElasticSearchObject>(pageData);
            // Simialr formatting to nmap
            returnString += $"- Version: {theObject.version.number} (name: {theObject.name}; cluster: {theObject.cluster_name}; Lucene: {theObject.version.lucene_version}){Environment.NewLine}";
            // Get indices
            string indexData = Web.DownloadString($"http://{ip}:{port}/_cat/indices"); // ?v for non-ordered data
            List<string> indexList = indexData.Split(Environment.NewLine.ToCharArray()).ToList();
            // Remove any empty indices
            indexList = indexList.Where(x => x.Length != 0).ToList();
            returnString += $"- Indexes: {indexList.Count}" + Environment.NewLine;
            foreach (string index in indexList)
            {
                List <string> items = index.Split(' ').ToList();
                // Remove any empty items
                items = items.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                // ?v -> Health, Status, Index, UUID, Pri, Rep, docs.count, docs.deleted, store.size, pri.store.size
                string indexName = items[2];
                string indexItems = items[6];
                returnString += $"-- Index: {indexName} ({indexItems} items){Environment.NewLine}";
                returnString += $"--- http://{ip}:9200/{indexName}/_search/?pretty&size={indexItems}{Environment.NewLine}";
            }
            returnString = returnString.Trim(Environment.NewLine.ToCharArray());
            return returnString;
        }
    }

#pragma warning disable IDE1006 // Naming Styles are supressed since these are case sensitive
    public class ElasticSearchObject
    {
        public string name { get; set; }
        public string cluster_name { get; set; }
        public string cluster_uuid { get; set; }
        public ElasticSearchObjectVersion version { get; set; }
        public string tagline { get; set; }
    }

    public class ElasticSearchObjectVersion
    {
        public string number { get; set; }
        public string build_flavor { get; set; }
        public string build_type { get; set; }
        public string build_hash { get; set; }
        public DateTime build_date { get; set; }
        public bool build_snapshot { get; set; }
        public string lucene_version { get; set; }
        public string minimum_wire_compatibility_version { get; set; }
        public string minimum_index_compatibility_version { get; set; }
    }
#pragma warning restore IDE1006 // Naming Styles
}
