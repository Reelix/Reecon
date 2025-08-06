using System;
using System.Drawing;
using System.Net;
using System.Text.Json;

namespace Reecon;

public static class Lookup
{
    public static void Scan(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Lookup Usage: reecon -lookup 8.8.8.8");
            return;
        }
        string ip = args[1];
        // No HTTPS without paying. Weird... But it is free, so hey!
        var result = Web.GetHTTPInfo($"http://ip-api.com/json/{ip}");
        if (result.StatusCode == HttpStatusCode.OK && result.PageText != null)
        {
            string pageText = result.PageText;
            JsonDocument data =  JsonDocument.Parse(pageText);
            var jsonRoot = data.RootElement;
            string status = jsonRoot.GetProperty("status").GetString() ?? "";
            if (status != "success")
            {
                Console.WriteLine($"Lookup Error for {ip}: " + status);
            }
            string country = jsonRoot.GetProperty("country").GetString() ?? "";
            string countryCode = jsonRoot.GetProperty("countryCode").GetString() ?? "";
            string region = jsonRoot.GetProperty("regionName").GetString() ?? "";
            string regionCode = jsonRoot.GetProperty("region").GetString() ?? "";
            string city = jsonRoot.GetProperty("city").GetString() ?? "";
            string isp = jsonRoot.GetProperty("isp").GetString() ?? "";
            string org = jsonRoot.GetProperty("org").GetString() ?? "";
            Console.WriteLine($"Lookup result for: {ip.Recolor(Color.Green)}");
            Console.WriteLine($"Country: {country} ({countryCode})");
            Console.WriteLine($"Region: {region} ({regionCode})");
            Console.WriteLine($"City: {city}");
            Console.WriteLine($"ISP: {isp}");
            if (org != string.Empty)
            {
                Console.WriteLine($"Organisation: {org}");
            }
        }
        else
        {
            Console.WriteLine($"Error - Unable to get information for {ip}");
        }
    }
}