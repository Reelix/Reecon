using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web.Script.Serialization;

namespace ReeCode
{
    public static class WebClientExtensions
    {
        /// <summary>
        /// Sets the Forwarded header.
        /// </summary>
        public static WebClient SetForwarded(this WebClient theWebClient, string via)
        {
            WebClient wc = theWebClient;
            // Since HttpRequestHeader.Forwarded is missing...
            theWebClient.Headers["Forwarded"] = via;
            return wc;
        }

        /// <summary>
        /// Sets the Via header.
        /// </summary>
        public static WebClient SetVia(this WebClient theWebClient, string via)
        {
            WebClient wc = theWebClient;
            theWebClient.Headers[HttpRequestHeader.Via] = via;
            return wc;
        }

        /// <summary>
        /// Sets the Cookie.
        /// </summary>
        public static WebClient SetCookie(this WebClient theWebClient, string cookie)
        {
            WebClient wc = theWebClient;
            theWebClient.Headers[HttpRequestHeader.Cookie] = cookie;
            return wc;
        }

        /*
        public static string GetCookie(this CookieAwareWebClient theWebClient)
        {
            WebClient wc = theWebClient;
            var headers = theWebClient.ResponseHeaders;
            var items = Enumerable
                .Range(0, headers.Count)
                .SelectMany(i => headers.GetValues(i)
                    .Select(v => Tuple.Create(headers.GetKey(i), v))
                );
            if (headers.AllKeys.Contains("Set-Cookie") && headers["Set-Cookie"] != "")
            {
                return headers["Set-Cookie"];
            }
            else
            {
                return "";
            }
        }
        */

        public static HttpStatusCode GetResponseCode(this WebClient theWebClient, string URL)
        {
            try
            {
                theWebClient.DownloadString(URL);
                return HttpStatusCode.OK;
            }
            catch (WebException wex)
            {
                return ((HttpWebResponse)wex.Response).StatusCode;
            }
        }

        /// <summary>
        /// Sets the Content Type
        /// </summary>
        public static WebClient SetContentType(this WebClient theWebClient, string contentType)
        {
            WebClient wc = theWebClient;
            theWebClient.Headers["Content-Type"] = contentType;
            return wc;
        }

        /// <summary>
        /// <para>Makes a WebClient GET request, and returns the result as a string.</para>
        /// <para>Similar to DownloadString, but with better functionality :)</para>
        /// </summary>
        public static string Get(this WebClient theWebClient, string URL, Dictionary<string, string> urlParams)
        {
            if (urlParams != null && urlParams.Any())
            {
                URL += "?";
                foreach (var item in urlParams)
                {
                    // HTML Entities?
                    URL += item.Key + "=" + item.Value + "&";
                }
                URL = URL.Trim('&');
            }
            try
            {
                string response = theWebClient.DownloadString(URL);
                return response;
            }
            catch (WebException wex)
            {
                if (wex.Response == null)
                {
                    Console.WriteLine("Error in Get - " + wex.Message);
                    return "";
                }
                if (((HttpWebResponse)wex.Response).StatusCode == HttpStatusCode.NotFound || ((HttpWebResponse)wex.Response).StatusCode == HttpStatusCode.Unauthorized)
                {
                    StreamReader sr1 = new StreamReader(wex.Response.GetResponseStream());
                    string theLine = sr1.ReadToEnd();
                    return theLine;
                }
                else
                {
                    Console.WriteLine("Error in Get - " + wex.Message);
                    return "";
                }
            }
        }

        /// <summary>
        /// Makes a WebClient POST request, and returns the result as a string.
        /// </summary>
        public static string Post(this WebClient theWebClient, string URL, Dictionary<string, string> postValues, bool isJSON = false)
        {
            NameValueCollection postCollection = new NameValueCollection();
            foreach (var item in postValues)
            {
                postCollection.Add(item.Key, item.Value);
            }
            try
            {
                if (isJSON)
                {
                    // As far as I know, you have to have this for POSTing JSON Data - Might be wrong?
                    theWebClient.SetContentType("application/json");

                    // TODO: Find a nice way to do Complex JSon Objects - Not just as a class....
                    // Instead of just { "name1" : "value1", "name2" : "value2" }
                    // Do { "name1" : { "subName1" : "subValue1", "subName2" : "subValue2" }, "name2" : "value2" }
                    var jsonData = postCollection.AllKeys.ToDictionary(x => x, x => postCollection[x]);
                    // using System.Web.Script.Serialization;
                    var json = new JavaScriptSerializer().Serialize(jsonData);

                    string response = theWebClient.UploadString(URL, json);
                    return response;
                }
                else
                {
                    byte[] responseBytes = theWebClient.UploadValues(URL, "POST", postCollection);
                    string responseString = Encoding.UTF8.GetString(responseBytes);
                    return responseString;
                }
            }
            catch (WebException wex)
            {
                if (wex.Response == null)
                {
                    Console.WriteLine("Error in Post - " + wex.Message);
                    return "";
                }
                if (((HttpWebResponse)wex.Response).StatusCode == HttpStatusCode.NotFound || ((HttpWebResponse)wex.Response).StatusCode == HttpStatusCode.Unauthorized)
                {
                    StreamReader sr1 = new StreamReader(wex.Response.GetResponseStream());
                    string theLine = sr1.ReadToEnd();
                    return theLine;
                }
                else
                {
                    Console.WriteLine("Error in Post - " + wex.Message);
                    return "";
                }
            }
        }
    }

    // For those times when you need persistence (PHPSESSID)
    public class CookieAwareWebClient : WebClient
    {
        // An aptly named container to store the Cookie
        public CookieContainer CookieContainer { get; private set; }

        public CookieAwareWebClient()
        {
            CookieContainer = new CookieContainer();
        }

        protected override WebRequest GetWebRequest(Uri address)
        {
            // Grabs the base request being made 
            var request = (HttpWebRequest)base.GetWebRequest(address);
            // Adds the existing cookie container to the Request
            request.CookieContainer = CookieContainer;
            return request;
        }
    }
}
