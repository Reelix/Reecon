using System;
using System.Drawing;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Reecon;

public static class ApiKey
{
    // Currently supported
    // Google Maps API Key
    // Telegram Bot Token
    public static void Search(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Key Scan Usage: reecon -apikey MYKEYHERE");
            return;
        }

        string apiKey = args[1];
        // https://github.com/streaak/keyhacks
        
        // Will shift this out into its own class when this gets busier
        // Google-Maps-API-key
        if (Regex.IsMatch(apiKey, "AIza[0-9A-Za-z\\-_]{35}"))
        {
            Console.WriteLine("Matches Google Maps Format - Testing...");

            // Sample: AIzaSyDe0LldBAVmT9ZzViJBZa0XQvR_iYEyA-0 (Don't ask)

            // Static Maps - TODO
            // Streetview - TODO
            // - https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={KEY_HERE}
            // - The Google Maps Platform server rejected your request. This API project is not authorized to use this API.
            // Embed - TODO
            // Directions - TODO
            // Firebase - TODO
            /*
            curl -X POST "https://firebaseremoteconfig.googleapis.com/v1/projects/{ProjectID}/namespaces/firebase:fetch?key={Firebase Key - Same as Google Key}" \
                -H "Content-Type: application/json" \
                -d '{
                  "appId": "1:{ProjectId}:android:{App ID - 22 chars long - Unsure if always 22 chars long}",
                  "appInstanceId": "required_but_unused_value"
                }'
                {
                  "entries": {
                    "biometricsEnabled": "true",
                    "trace_list": ""
                  },
                  "state": "UPDATE",
                  "templateVersion": "22"
                }
                
                This seems to be read only - Can't write to it, although it may contain some sensitive info?
                
                */

            // Geocoding - TODO
            // Distance Matrix
            string googleDistanceMatrix =
                "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=";
            var httpInfo = Web.GetHttpInfo(googleDistanceMatrix + apiKey);
            if (httpInfo.StatusCode == HttpStatusCode.OK && httpInfo.PageText != null)
            {
                if (httpInfo.PageText.Contains("The provided API key is invalid."))
                {
                    Console.WriteLine("- Google Maps - Distance Matrix - The API key is invalid.");
                }
                else if (httpInfo.PageText.Contains("You’re calling a legacy API, which is not enabled for your project."))
                {
                    Console.WriteLine("- Google Maps - Distance Matrix - Legacy API Key (Not Enabled)");
                }
                else
                {
                    Console.WriteLine($"- Google Maps - Distance Matrix - The API key is {"valid".Recolor(Color.Green)}.");
                }
            }

            // Find Place from Text
            string googleFindPlaceFromText =
                "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=";
            httpInfo = Web.GetHttpInfo(googleFindPlaceFromText + apiKey);
            if (httpInfo.StatusCode == HttpStatusCode.OK && httpInfo.PageText != null)
            {
                if (httpInfo.PageText.Contains("The provided API key is invalid."))
                {
                    Console.WriteLine("- Google Maps - Find Place from Text - The API key is invalid.");
                }
                else if (httpInfo.PageText.Contains("You’re calling a legacy API, which is not enabled for your project."))
                {
                    Console.WriteLine("- Google Maps - Find Place from Text - Legacy API Key (Not Enabled)");
                }
                else
                {
                    Console.WriteLine($"- Google Maps - Find Place from Text - The API key is {"valid".Recolor(Color.Green)}.");
                }
            }

            // Autocomplete
            string googleAutocomplete = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=";
            httpInfo = Web.GetHttpInfo(googleAutocomplete + apiKey);
            if (httpInfo.StatusCode == HttpStatusCode.OK && httpInfo.PageText != null)
            {
                if (httpInfo.PageText.Contains("The provided API key is invalid."))
                {
                    Console.WriteLine("- Google Maps - Autocomplete - The API key is invalid.");
                }
                else if (httpInfo.PageText.Contains("You’re calling a legacy API, which is not enabled for your project."))
                {
                    Console.WriteLine("- Google Maps - Autocomplete - Legacy API Key (Not Enabled)");
                }
                else
                {
                    Console.WriteLine($"- Google Maps - Autocomplete - The API key is {"valid".Recolor(Color.Green)}.");
                }
            }

            // Elevation - TODO
            // Timezone - TODO
        }

        // Telegram Bot Token
        // /^[0-9]{8,10}:[a-zA-Z0-9_-]{35}$/
        if (Regex.IsMatch(apiKey, "^[0-9]{8,10}:[a-zA-Z0-9_-]{35}$"))
        {
            Console.WriteLine("Matches Telegram Bot Token Format - Testing...");
            string telegramBotToken = $"https://api.telegram.org/bot{apiKey}/getMe";
            // /getUpdates <---
            // /getWebhookInfo
            // /getMyCommands
            var httpInfo = Web.GetHttpInfo(telegramBotToken);
            if (httpInfo.StatusCode == HttpStatusCode.OK && httpInfo.PageText != null)
            {
                Console.WriteLine($"- Telegram Bot Token - The Bot Token is {"valid".Recolor(Color.Green)}.");
                JsonDocument jsonData = JsonDocument.Parse(httpInfo.PageText);
                JsonElement result = jsonData.RootElement.GetProperty("result");
                if (result.TryGetProperty("first_name", out JsonElement jsonFirstName))
                {
                    Console.WriteLine($"-- First Name: {jsonFirstName.GetString()}");
                }
                if (result.TryGetProperty("username", out JsonElement jsonUsername))
                {
                    Console.WriteLine($"-- Username: {jsonUsername.GetString()}");
                }
                Console.WriteLine("Woof");
                
                // Get Chat Info:
                // https://api.telegram.org/bot{apiKey}/getChat?chat_id=-4862820035
                
                // Get Chat Admins:
                // https://api.telegram.org/bot{apiKey}/getChatAdministrators?chat_id=-4862820035
                
                // Get Chat Member Count
                // https://api.telegram.org/bot{apiKey}/getChatMemberCount?chat_id=-4862820035
                
                // Find your own group ID
                // Forward a random message to @getidsbot - Look at Origin Chat ID
                
                // Forward message from one group to another
                // curl https://api.telegram.org/bot{apiKey}/forwardMessage -d from_chat_id=-fromGroupId -d chat_id=-toGroupId -d message_id=1
                // Note: Some ID's may be deleted - Go from 1 to ...
                
            }
            else if (httpInfo.StatusCode == HttpStatusCode.Unauthorized)
            {
                Console.WriteLine("- Telegram Bot Token - The Bot Token is invalid.");
            }
        }
    }
}