using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ReeRecon
{
    class HTTP
    {
        public string GetTitle(string ip, int port, bool isHTTPS)
        {
            string pageData = "";
            string urlPrefix = "http";
            if (isHTTPS)
            {
                urlPrefix += "s";
            }
            WebResponse theResponse = null;
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(urlPrefix + "://" + ip + ":" + port);
                StreamReader readStream = new StreamReader(request.GetResponse().GetResponseStream()); 
                pageData = readStream.ReadToEnd();
            }
            catch (WebException ex)
            {
                StreamReader readStream = new StreamReader(((HttpWebResponse)ex.Response).GetResponseStream());
                pageData = readStream.ReadToEnd();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Fatal Woof");
            }
            if (pageData.Contains("<title>") && pageData.Contains("</title>"))
            {
                pageData = pageData.Remove(0, pageData.IndexOf("<title>") + "<title>".Length);
                pageData = pageData.Substring(0, pageData.IndexOf("</title>"));
                return pageData;
            }
            // string pageData = WebClient.C
            return "";
        }

        public WebHeaderCollection GetHeader(string ip, int port = 80)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://" + ip + ":" + port);
            request.Method = "HEAD";
            // Ignore invalid SSL Cert
            // request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;

            // HttpWebRequest craps out if the response is a 401 Unauthorized / 403 Forbidden page and throws a WebException
            WebResponse theResponse = null;
            try
            {
                theResponse = request.GetResponse();
                return theResponse.Headers;
            }
            catch (WebException ex)
            {
                theResponse = (HttpWebResponse)ex.Response;
                return theResponse.Headers;
            }
            catch
            {
                return null;
            }
        }

        // TODO: Check for 403? Is a double response even needed?
        public (X509Certificate2 cert, WebHeaderCollection headers) GetSSLCertAndHeaders(string ip, int port = 443)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://" + ip + ":" + port);
            request.Method = "HEAD";
            // Ignore invalid SSL Cert
            request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;

            WebResponse theResponse = null;
            WebHeaderCollection headers = null;
            try
            {
                theResponse = request.GetResponse();
                headers = theResponse.Headers;
            }
            catch (WebException ex)
            {
                theResponse = (HttpWebResponse)ex.Response;
                headers = theResponse.Headers;
            }
            catch
            {
                Console.WriteLine("http - GetSSLCertAndHeaders Error - Unknown error ._.");
                return (null, null);
            }
            theResponse.Close();
            X509Certificate2 theCert = new X509Certificate2(request.ServicePoint.Certificate);
            return (theCert, headers);
        }
    }
}
