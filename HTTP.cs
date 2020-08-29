using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using System.Collections.Generic;

namespace Reecon
{
    class HTTP
    {
        public static string GetInfo(string ip, int port, bool isHTTPS)
        {
            string url = "http";
            if (isHTTPS)
            {
                url += "s";
            }
            url += $"://{ip}:{port}/";

            var httpInfo = GetHTTPInfo(url);
            if (httpInfo == (0, null, null, null, null, null))
            {
                return "";
            }
            string portData = FormatResponse(httpInfo.StatusCode, httpInfo.PageTitle, httpInfo.PageText, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert);
            string commonFiles = Web.FindCommonFiles(url);
            if (commonFiles != "")
            {
                portData += Environment.NewLine + commonFiles;
            }
            string baseLFI = TestBaseLFI(ip, port);
            if (baseLFI != "")
            {
                portData += Environment.NewLine + baseLFI + Environment.NewLine;
            }
            if (portData == "")
            {
                portData = "- No Info Found";
            }
            return portData;
        }

        private static (HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, WebHeaderCollection Headers, X509Certificate2 SSLCert) GetHTTPInfo(string url)
        {
            string pageTitle = "";
            string pageText = "";
            string dns = "";
            HttpStatusCode statusCode = new HttpStatusCode();
            WebHeaderCollection headers = null;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            try
            {
                // Ignore invalid SSL Cert
                request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                request.AllowAutoRedirect = false;

                // Can crash here due to a WebException on 401 Unauthorized / 403 Forbidden errors, so have to do some things twice
                request.Timeout = 5000;
                using (var response = request.GetResponse() as HttpWebResponse)
                {
                    statusCode = response.StatusCode;
                    dns = response.ResponseUri.DnsSafeHost;
                    headers = response.Headers;
                    using (StreamReader readStream = new StreamReader(response.GetResponseStream()))
                    {
                        pageText = readStream.ReadToEnd();
                    }
                    response.Close();
                }
            }
            catch (WebException ex)
            {
                if (ex.Response == null)
                {
                    if (ex.Message != null)
                    {
                        if (ex.Message.Trim() == "The request was aborted: Could not create SSL/TLS secure channel.")
                        {
                            Console.WriteLine("GetHTTPInfo.Error.SSLTLS - Bug Reelix to fix this");
                        }
                        else if (ex.Message.Trim() == "The underlying connection was closed: An unexpected error occurred on a send.")
                        {
                            // Ignore it
                        }
                        else if (ex.Message.Trim() == "The operation has timed out.")
                        {
                            // Ignore it
                        }
                        else if (ex.Message.Trim() == "Error: SecureChannelFailure (Authentication failed, see inner exception.)")
                        {
                            // Ignore it - Should we?
                        }
                        else if (ex.Message.Trim() == "Error: ConnectFailure (Connection refused)" || ex.Message.Trim() == "Error: ConnectFailure (No route to host)")
                        {
                            // The port is probably closed to us
                            // Ignore it - It's handled elswhere
                        }
                        else
                        {
                            Console.WriteLine("GetHTTPInfo.Error: " + ex.Message);
                        }
                    }
                    return (statusCode, null, null, null, null, null);
                }
                HttpWebResponse response = (HttpWebResponse)ex.Response;
                statusCode = response.StatusCode;
                dns = response.ResponseUri.DnsSafeHost;
                headers = response.Headers;
                using (StreamReader readStream = new StreamReader(response.GetResponseStream()))
                {
                    pageText = readStream.ReadToEnd();
                }
                response.Close();
            }
            catch (Exception ex)
            {
                // Something went really wrong...
                Console.WriteLine("GetHTTPInfo - Fatal Woof :( - " + ex.Message);
                return (statusCode, null, null, null, null, null);
            }

            if (pageText.Contains("<title>") && pageText.Contains("</title>"))
            {
                pageTitle = pageText.Remove(0, pageText.IndexOf("<title>") + "<title>".Length);
                pageTitle = pageTitle.Substring(0, pageTitle.IndexOf("</title>"));
            }
            X509Certificate2 cert = null;
            if (request.ServicePoint.Certificate != null)
            {
                cert = new X509Certificate2(request.ServicePoint.Certificate);
            }
            return (statusCode, pageTitle, pageText, dns, headers, cert);
        }

        private static string TestBaseLFI(string ip, int port)
        {
            string result = General.BannerGrab(ip, port, "GET /../../../../../../etc/passwd HTTP/1.1" + Environment.NewLine + "Host: " + ip + Environment.NewLine + Environment.NewLine, 2500);
            if (result.Contains("root"))
            {
                return "- /etc/passwd File Found VIA Base LFI! --> GET /../../../../../../etc/passwd" + Environment.NewLine + result;
                // Need to format this better...

            }
            result = General.BannerGrab(ip, port, "GET /../../../../../../windows/win.ini HTTP/1.1" + Environment.NewLine + "Host: " + ip + Environment.NewLine + Environment.NewLine, 2500);
            if (result.Contains("for 16-bit app support"))
            {
                return "- /windows/win.ini File Found VIA Base LFI! --> GET /../../../../../../windows/win.ini" + Environment.NewLine + result;
            }
            return "";
        }

        private static string FormatResponse(HttpStatusCode StatusCode, string PageTitle, string PageText, string DNS, WebHeaderCollection Headers, X509Certificate2 SSLCert)
        {
            string responseText = "";
            List<string> headerList = new List<string>();
            if (Headers != null)
            {
                headerList = Headers.AllKeys.ToList();
            }
            if (StatusCode != HttpStatusCode.OK)
            {
                // There's a low chance that it will return a StatusCode that is not in the HttpStatusCode list in which case (int)StatusCode will crash
                if (StatusCode == HttpStatusCode.MovedPermanently)
                {
                    if (Headers != null && Headers.Get("Location") != null)
                    {
                        responseText += "- Moved Permanently" + Environment.NewLine;
                        responseText += "-> Location: " + Headers.Get("Location") + Environment.NewLine;
                        headerList.Remove("Location");
                    }
                }
                else if (StatusCode == HttpStatusCode.Redirect)
                {
                    if (Headers != null && Headers.Get("Location") != null)
                    {
                        responseText += "- Redirect" + Environment.NewLine;
                        responseText += "-> Location: " + Headers.Get("Location") + Environment.NewLine;
                        headerList.Remove("Location");
                    }
                }
                else if (StatusCode != HttpStatusCode.OK)
                {
                    try
                    {
                        responseText += "- Weird Status Code: " + (int)StatusCode + " " + StatusCode + Environment.NewLine;
                    }
                    catch
                    {
                        responseText += "- Unknown Status Code: " + " " + StatusCode + Environment.NewLine;
                    }
                    if (Headers != null && Headers.Get("Location") != null)
                    {
                        responseText += "-> Location: " + Headers.Get("Location") + Environment.NewLine;
                        headerList.Remove("Location");
                    }
                }
            }
            if (!string.IsNullOrEmpty(PageTitle))
            {
                responseText += "- Page Title: " + PageTitle + Environment.NewLine;
            }
            if (PageText.Length > 0)
            {
                if (PageText.Length < 250)
                {
                    responseText += "- Page Text: " + PageText.Trim() + Environment.NewLine;
                }
                if (PageText.Contains("/wp-content/themes/") && PageText.Contains("/wp-includes/"))
                {
                    responseText += "- Wordpress detected! Run wpscan!" + Environment.NewLine;
                    responseText += "-- hydra -L users.txt -P passwords.txt site.com http-post-form \"/blog/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location\" -I -t 50" + Environment.NewLine;
                }
            }
            if (!string.IsNullOrEmpty(DNS))
            {
                responseText += "- DNS: " + DNS + Environment.NewLine;
            }
            if (headerList.Any())
            {
                headerList = Headers.AllKeys.ToList();
                // Useful info
                if (headerList.Contains("Server"))
                {
                    headerList.Remove("Server");
                    string serverText = Headers.Get("Server").Trim();
                    responseText += "- Server: " + serverText + Environment.NewLine;
                    if (serverText.StartsWith("MiniServ/"))
                    {
                        responseText += "-- Webmin Server Detected" + Environment.NewLine;
                        // 1.890, 1.900-1.920 - http://www.webmin.com/changes.html
                        if (serverText.StartsWith("MiniServ/1.890") || serverText.StartsWith("MiniServ/1.900") || serverText.StartsWith("MiniServ/1.910") || serverText.StartsWith("MiniServ/1.920"))
                        {
                            responseText += "--- Possible Vulnerable Version: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/webmin_backdoor.rb" + Environment.NewLine;
                        }
                    }
                }
                // Useful info
                if (headerList.Contains("X-Powered-By"))
                {
                    headerList.Remove("X-Powered-By");
                    responseText += "- X-Powered-By: " + Headers.Get("X-Powered-By") + Environment.NewLine;
                }
                // Requires a login
                if (headerList.Contains("WWW-Authenticate"))
                {
                    headerList.Remove("WWW-Authenticate");
                    responseText += "- WWW-Authenticate: " + Headers.Get("WWW-Authenticate") + Environment.NewLine;
                }
                // Kabana
                if (headerList.Contains("kbn-name"))
                {
                    headerList.Remove("kbn-name");
                    responseText += "- kbn-name: " + Headers.Get("kbn-name") + Environment.NewLine;
                    responseText += "-- You should get more kibana-based info further down" + Environment.NewLine; ;
                }
                if (headerList.Contains("kbn-version"))
                {
                    headerList.Remove("kbn-version");
                    responseText += "- kbn-version: " + Headers.Get("kbn-version") + Environment.NewLine;
                }
                // Useful cookies
                if (headerList.Contains("Set-Cookie"))
                {
                    headerList.Remove("Set-Cookie");
                    responseText += "- Set-Cookie: " + Headers.Get("Set-Cookie") + Environment.NewLine;
                }
                // Fun content types
                if (headerList.Contains("Content-Type"))
                {
                    string contentType = Headers.Get("Content-Type");
                    if (contentType != "text/html")
                    {
                        // A unique content type - Might be interesting
                        responseText += "- Content-Type: " + Headers.Get("Content-Type") + Environment.NewLine;
                    }
                }
                responseText += "- Other Headers: " + string.Join(",", headerList) + Environment.NewLine;
            }
            if (SSLCert != null)
            {
                string certIssuer = SSLCert.Issuer;
                string certSubject = SSLCert.Subject;
                // string certAltName = SSLCert.SubjectName.Name;
                responseText += "- SSL Cert Issuer: " + certIssuer + Environment.NewLine;
                responseText += "- SSL Cert Subject: " + certSubject + Environment.NewLine;
                if (SSLCert.Extensions != null)
                {
                    X509ExtensionCollection extensionCollection = SSLCert.Extensions;
                    foreach (X509Extension extension in extensionCollection)
                    {
                        string extensionType = extension.Oid.FriendlyName;
                        if (extensionType == "Subject Alternative Name")
                        {

                            AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                            List<string> formattedValues = asndata.Format(true).Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                            string itemList = "";
                            foreach (string item in formattedValues)
                            {
                                string theItem = item;
                                theItem = theItem.Replace("DNS Name=", "");
                                if (theItem.Contains("("))
                                {
                                    theItem = theItem.Remove(0, theItem.IndexOf("(") + 1).Replace(")", "");
                                    itemList += theItem + ",";
                                }
                                else
                                {
                                    itemList += theItem + ",";
                                }
                            }
                            itemList = itemList.Trim(',');
                            responseText += "- Subject Alternative Name: " + itemList + Environment.NewLine;
                        }
                    }
                }
            }
            // Clean off any redundant newlines
            responseText = responseText.TrimEnd(Environment.NewLine.ToCharArray());
            return responseText;
        }
    }
}
