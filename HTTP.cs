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
        // Split to 4 in threads?
        public (HttpStatusCode StatusCode, string Title, string DNS, WebHeaderCollection Headers, X509Certificate2 SSLCert) GetHTTPInfo(string ip, int port, bool isHTTPS)
        {
            string pageTitle = "";
            string pageData = "";
            string dns = "";
            string urlPrefix = "http";
            HttpStatusCode statusCode = new HttpStatusCode();
            if (isHTTPS)
            {
                urlPrefix += "s";
            }
            WebHeaderCollection headers = null;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(urlPrefix + "://" + ip + ":" + port);
            try
            {
                // Ignore invalid SSL Cert
                request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                request.AllowAutoRedirect = false;

                // Can crash here due to a WebException on 401 Unauthorized / 403 Forbidden errors, so have to do some things twice
                using (var response = request.GetResponse() as HttpWebResponse)
                {
                    statusCode = response.StatusCode;
                    dns = response.ResponseUri.DnsSafeHost;
                    headers = response.Headers;
                    using (StreamReader readStream = new StreamReader(response.GetResponseStream()))
                    {
                        pageData = readStream.ReadToEnd();
                    }
                    response.Close();
                }
            }
            catch (WebException ex)
            {
                if (ex.Response == null)
                {
                    // WebClient wc = new WebClient();
                    // string someString = wc.DownloadString("https://" + ip + ":" + port);
                    return (statusCode, null, null, null, null);
                }
                HttpWebResponse response = (HttpWebResponse)ex.Response;
                statusCode = response.StatusCode;
                dns = response.ResponseUri.DnsSafeHost;
                headers = response.Headers;
                using (StreamReader readStream = new StreamReader(response.GetResponseStream()))
                {
                    pageData = readStream.ReadToEnd();
                }
                response.Close();
            }
            catch (Exception ex)
            {
                // Something went really wrong...
                Console.WriteLine("GetHTTPInfo - Fatal Woof :(: " + ex.Message);
                return (statusCode, null, null, null, null);
            }

            if (pageData.Contains("<title>") && pageData.Contains("</title>"))
            {
                pageTitle = pageData.Remove(0, pageData.IndexOf("<title>") + "<title>".Length);
                pageTitle = pageTitle.Substring(0, pageTitle.IndexOf("</title>"));
            }
            X509Certificate2 cert = null;
            if (request.ServicePoint.Certificate != null)
            {
                cert = new X509Certificate2(request.ServicePoint.Certificate);
            }
            return (statusCode, pageTitle, dns, headers, cert);
        }

        public string FormatResponse(HttpStatusCode StatusCode, string Title, string DNS, WebHeaderCollection Headers, X509Certificate2 SSLCert)
        {
            string responseText = "";

            if (StatusCode != HttpStatusCode.OK)
            {
                // There's a low chance that it will return a StatusCode that is not in the HttpStatusCode list in which case (int)StatusCode will crash
                try
                {
                    responseText += Environment.NewLine + "- Non-OK Status Code: " + (int)StatusCode + " " + StatusCode;
                }
                catch
                {
                    responseText += Environment.NewLine + "- Unknown Status Code: " + " " + StatusCode;
                }

                if (StatusCode != HttpStatusCode.OK)
                {
                    if (Headers != null && Headers.Get("Location") != null)
                    {
                        responseText += Environment.NewLine + "- Location: " + Headers.Get("Location");
                    }
                }
            }
            if (!string.IsNullOrEmpty(Title))
            {
                responseText += Environment.NewLine + "- Page Title: " + Title;
            }
            if (!string.IsNullOrEmpty(DNS))
            {
                responseText += Environment.NewLine + "- DNS: " + DNS;
            }
            if (Headers != null)
            {
                responseText += Environment.NewLine + "- Headers: " + string.Join(",", Headers.AllKeys);
                if (Headers.Get("Server") != null)
                {
                    responseText += Environment.NewLine + "- Server: " + Headers.Get("Server");
                }
                if (Headers.Get("X-Powered-By") != null)
                {
                    responseText += Environment.NewLine + "- X-Powered-By: " + Headers.Get("X-Powered-By");
                }
                if (Headers.Get("WWW-Authenticate") != null)
                {
                    responseText += Environment.NewLine + "- WWW-Authenticate: " + Headers.Get("WWW-Authenticate");
                }
            }
            if (SSLCert != null)
            {
                string certIssuer = SSLCert.Issuer;
                string certSubject = SSLCert.Subject;
                // string certAltName = SSLCert.SubjectName.Name;
                responseText += Environment.NewLine + "- SSL Cert Issuer: " + certIssuer;
                responseText += Environment.NewLine + "- SSL Cert Subject: " + certSubject;
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
                            responseText += Environment.NewLine + "- Subject Alternative Name: " + itemList;
                        }
                    }
                }
            }
            return responseText;
        }
    }
}
