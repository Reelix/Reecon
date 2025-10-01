using System;
using static Reecon.Web;

namespace Reecon
{
    internal static class Http //80 / 8080 / 8000 (Also used for 443, HTTPS)
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            string result = GetInfoMain(target, port, false);
            if (result.Contains("Page Text: Client sent an HTTP request to an HTTPS server."))
            {
                // Whoops - HTTPS Server!
                // TODO: This still returns as HTTP instead of HTTPS though - Need to find a way to change it...
                Console.WriteLine("Whoops - HTTPS Server - Not HTTP - Bug Reelix to update this in General.MultiBannerGrab!");
                result = GetInfoMain(target, port, true);
            }
            return ("HTTP", result);
        }

        public static string GetInfoMain(string target, int port, bool isHttps)
        {
            try
            {
                string url;
                if (isHttps)
                {
                    url = port == 443 ? $"https://{target}/" : $"https://{target}:{port}/";
                }
                else
                {
                    url = port == 80 ? $"http://{target}/" : $"http://{target}:{port}/";
                }
                HttpInfo httpInfo = GetHttpInfo(url);
                
                // AdditionalInfo with a single word is actually broken
                // May need to shift these out somewhere else
                if (httpInfo.AdditionalInfo != null && !httpInfo.AdditionalInfo.Contains(' '))
                {
                    if (httpInfo.AdditionalInfo == "Timeout")
                    {
                        return "- Timeout";
                    }
                    else if (httpInfo.AdditionalInfo == "WeirdSSL")
                    {
                        return "- It's SSL, but can't connect with https for some reason :(";
                    }
                    else if (httpInfo.AdditionalInfo == "InvalidDNS")
                    {
                        return $"- The url {url} does not exist - Maybe fix your /etc/hosts file?";
                    }
                    else if (httpInfo.AdditionalInfo == "ConnectionRefused")
                    {
                        return "- Connection Refused - Is it still online?";
                    }
                    else if (httpInfo.AdditionalInfo == "SSL_ERROR_SSL")
                    {
                        return "- SSL Handshake Failed - You may want to look into this :/";
                    }
                    // OK Things
                    else if (httpInfo.AdditionalInfo != null && !httpInfo.AdditionalInfo.Contains(' '))
                    {
                        return $"- {httpInfo.AdditionalInfo.TrimEnd(Environment.NewLine.ToCharArray())}";
                    }
                }
                // Except for this
                else if (httpInfo.StatusCode == null)
                {
                    return "";
                }
                string portData = Web.ParseHttpInfo(httpInfo);

                // The final Environment.NewLine is stripped from portData, so we need to re-add it
                if (httpInfo.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    portData += Environment.NewLine + "- Skipping file enumeration due to unauthorized result" + Environment.NewLine;
                    portData += $"-- hydra -L users.txt -P passwords.txt -s {port} -f {target} http-get /" + Environment.NewLine;
                }
                else
                {
                    string commonFiles = Web.FindCommonFiles(url);
                    if (commonFiles != "")
                    {
                        portData += Environment.NewLine + commonFiles;
                    }
                }
                string baseLfi = TestBaseLfi(target, port);
                if (baseLfi != "")
                {
                    portData += Environment.NewLine + baseLfi + Environment.NewLine;
                }
                if (portData == "")
                {
                    portData = "- No Info Found";
                }
                return portData.TrimEnd(Environment.NewLine.ToCharArray());
            }
            catch (Exception ex)
            {
                General.HandleUnknownException(ex);
                return "";
            }
        }
    }
}
