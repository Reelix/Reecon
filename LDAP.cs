using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Reecon
{
    class LDAP // Port 389 / 636 (LDAPS)
    {
        // Linux requires: https://packages.ubuntu.com/focal-updates/amd64/libldap-2.4-2/download
        static string rootDseString = "";

        public static (string PortName, string PortData) GetInfo(string ip, int port)
        {
            string returnInfo = "";
            string checkCanRun = CanLDAPRun();
            if (checkCanRun != null)
            {
                // https://github.com/dotnet/runtime/issues/69456
                return ("LDAP", checkCanRun);
            }
            returnInfo = LDAP.GetDefaultNamingContext(ip, port);
            returnInfo += LDAP.GetAccountInfo(ip, port, null);
            returnInfo = returnInfo.Trim(Environment.NewLine.ToCharArray());
            return ("LDAP", returnInfo.Trim(Environment.NewLine.ToCharArray()));
        }

        public static string CanLDAPRun()
        {
            string toReturn = null;
            try
            {
                LdapConnection connection = new LdapConnection("");
                return toReturn;
            }
            catch (TypeInitializationException tex)
            {
                try
                {
                    throw tex.InnerException;
                }
                catch (DllNotFoundException dex)
                {
                    if (dex.Message.StartsWith("Unable to load shared library '"))
                    {
                        string missingLib = dex.Message.Remove(0, dex.Message.IndexOf("Unable to load shared library '") + ("Unable to load shared library '").Length);
                        missingLib = missingLib.Substring(0, missingLib.IndexOf("'"));
                        toReturn = "- LDAP.GetInfo - Cannot run without DLL: " + missingLib + Environment.NewLine;
                        if (RuntimeInformation.ProcessArchitecture.ToString() == "Arm64")
                        {
                            toReturn += "-- Detected Arm64 - Download + Install: http://ports.ubuntu.com/pool/main/o/openldap/libldap-2.4-2_2.4.49+dfsg-2ubuntu1_arm64.deb";
                            return toReturn;
                        }
                        else
                        {
                            toReturn += "-- Detected: " + RuntimeInformation.ProcessArchitecture.ToString() + " - Bug Reelix";
                            return toReturn;
                        }
                    }
                    else
                    {
                        toReturn = "- LDAP.GetInfo - Unknown Error 1 - Bug Reelix";
                        return toReturn;
                    }
                }
                catch
                {
                    toReturn = "- LDAP.GetInfo - Unknown Error 2 - Bug Reelix";
                    return toReturn;
                }
            }
        }

        public static string GetDefaultNamingContext(string ip, int port, bool raw = false)
        {
            string ldapInfo = string.Empty;
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ip); //, port);
            NetworkCredential creds = new NetworkCredential();
            //creds.UserName = "support\\ldap";
            // creds.UserName = "anonymous";
            // creds.Password = "test";
            //creds.Password = original;
            LdapConnection connection = new LdapConnection(identifier, creds);
            connection.AuthType = AuthType.Anonymous;
            connection.SessionOptions.ProtocolVersion = 3;
            if (identifier.PortNumber == 389)
            {
                // This currently does not work - Need to fix it some day
                // Console.WriteLine("Setting SSL!");
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

            }
            SearchRequest searchRequest = new SearchRequest("", "(objectClass=computer)", SearchScope.Base);
            try
            {
                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                SearchResultEntryCollection searchEntries = searchResponse.Entries;

                if (searchResponse.Entries.Count > 0)
                {
                    SearchResultEntry entry = searchResponse.Entries[0];
                    rootDseString = entry.Attributes["defaultNamingContext"][0].ToString();
                    // string serverName = entry.Attributes["serverName"][0].ToString();
                    return rootDseString;
                }
                else
                {
                    throw new InvalidOperationException("defaultNamingContext not found in RootDSE.");
                    /*
                    Console.WriteLine("Found: " + searchEntries.Count + " entries.");
                    if (searchEntries[0].Attributes.Contains("defaultNamingContext"))
                    {
                        DirectoryAttribute coll = searchEntries[0].Attributes["defaultNamingContext"];
                        string defaultNamingContext = "";
                        if (General.GetOS() == General.OS.Windows)
                        {
                            if (coll[0].GetType() == typeof(String))
                            {
                                defaultNamingContext = coll[0].ToString();
                            }
                            else
                            {
                                byte[] byteList = (byte[])coll[0];
                                defaultNamingContext = Encoding.UTF8.GetString(byteList);
                            }
                        }
                        else
                        {
                            defaultNamingContext = coll[0].ToString();
                        }
                        rootDseString = defaultNamingContext;

                        if (raw)
                        {
                            ldapInfo = defaultNamingContext;
                        }
                        else
                        {
                            ldapInfo += $"- defaultNamingContext: {defaultNamingContext}" + Environment.NewLine;
                        }
                    }
                    else if (searchEntries[0].Attributes.Contains("objectClass"))
                    {
                        string objectClass = searchEntries[0].Attributes["objectClass"].ToString();
                        ldapInfo = "- No defaultNamingContext, but we have an objectClass - Bug Reelix To Fix: " + objectClass + Environment.NewLine;
                    }
                    else
                    {
                        ldapInfo = "- Error: No defaultNamingContext! Keys: " + searchEntries[0].Attributes.Count + Environment.NewLine;
                        foreach (var item in searchEntries[0].Attributes)
                        {
                            Console.WriteLine("Bug Reelix To Fix");
                            //ldapInfo += "- Found Key: " + item.Name + " with value " + item.GetValue<string>() + Environment.NewLine;
                        }
                    }
                    // var searchEntries = ldapConnection.Search(null, "(objectclass=*)", scope: Native.LdapSearchScope.LDAP_SCOPE_BASE);
                    */
                }
            }
            catch (Exception ex)
            {
                ldapInfo = "- Error: " + ex.Message;
            }
            return ldapInfo;
        }

        // Any time I try to get the LDAP Server SSL Cert details
        // connection.SessionOptions.VerifyServerCertificate = new VerifyServerCertificateCallback(OnVerifyServerCertificateCallback);
        // It freaks out with "The LDAP server is unavailable."
        static bool OnVerifyServerCertificateCallback(LdapConnection ldapConnection, X509Certificate certificate)
        {
            Console.WriteLine("Callback hit"); // Never gotten this hit...
            string issuer = certificate.Issuer;
            string subject = certificate.Subject;
            if (issuer != subject)
            {
                //ldapInfo += "-- LDAP SSL Cert Subject: " + subject;
            }
            /*
            Console.WriteLine("Issuer: " + e.Certificate.Issuer);
            Console.WriteLine("Subject: " + e.Certificate.Subject);
            Console.WriteLine("Raw: " + e.Certificate.GetRawCertDataString());
            */
            return true;
        }

        /*
        public static string GetLDAPCertInfo(string ip)
        {
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ip);
            LdapConnection connection = new LdapConnection(identifier, null)
            {
                AuthType = AuthType.Anonymous,
                SessionOptions =
                {
                    ProtocolVersion = 3
                }
            };
            connection.SessionOptions.VerifyServerCertificate = new VerifyServerCertificateCallback(VerifyServerCertificate);
        }
        */



        public static string GetAccountInfo(string ip, int port, string username = null, string password = null)
        {
            string ldapInfo = string.Empty;
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ip, port);
            NetworkCredential creds = new NetworkCredential(username, password);
            //creds.UserName = "support\\ldap";
            // creds.Domain = "cicada.htb";
            creds.UserName = username;
            creds.Password = password;
            if (username == null && password == null)
            {
                creds = null;
            }
            else
            {
                Console.WriteLine("Testing LDAP with: " + username + ":" + password);
            }
            LdapConnection connection = new LdapConnection(identifier, creds);


            if (port == 389)
            {
                // Normally basic - Why Negotiate Now... ????
                connection.AuthType = AuthType.Negotiate;
            };
            //required for searching on root of ldap directory https://github.com/dotnet/runtime/issues/64900
            // connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

            connection.SessionOptions.ProtocolVersion = 3;

            if (port == 389)
            {
                // For AuthType.Negotiate
                connection.SessionOptions.VerifyServerCertificate += (conn, cert) => { return true; };
                connection.SessionOptions.StartTransportLayerSecurity(null);

            }
             
            try
            {
                connection.Bind();
                // Console.WriteLine("Creds are correct!");
                if (rootDseString == "")
                {
                    rootDseString = LDAP.GetDefaultNamingContext(ip, port);
                    // Console.WriteLine("Found Default Naming Context: " + rootDseString);
                }
                List<SearchResponse> searchResponseList = new List<SearchResponse>();
                SearchResponse searchResponse = null;
                int maxResultsToRequest = 100;
                // Over 100 can cause a "The size limit was exceeded" error.
                PageResultRequestControl pageRequestControl = new PageResultRequestControl(maxResultsToRequest);
                PageResultResponseControl pageResponseControl;
                SearchRequest searchRequest = new SearchRequest(rootDseString, "(objectclass=user)", SearchScope.Subtree);
                searchRequest.Controls.Add(pageRequestControl);

                // Iterate through the responses and add each to the searchResponseList (Pagination)
                while (true)
                {
                    // Console.WriteLine("Paging...");
                    // Console.WriteLine(1);
                    // This complains about a bind error - Why?
                    // Does it only happen in cases where there are more than 100 pages?
                    try
                    {
                        searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                    }
                    catch (DirectoryOperationException doex)
                    {
                        if (doex.Message.Contains("In order to perform this operation a successful bind must be completed on the connection."))
                        {
                            break;
                        }
                        else
                        {
                            Console.WriteLine("Fatal error in LDAP.GetAccountInfo - doex Error: " + doex.Message);
                            Environment.Exit(0);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Fatal error in LDAP.GetAccountInfo - ex Error: " + ex.Message);
                        Environment.Exit(0);
                    }
                    // Console.WriteLine(2);
                    // Console.WriteLine("Adding a searchResponse with " + searchResponse.Entries.Count + " entries.");
                    searchResponseList.Add(searchResponse);
                    // Console.WriteLine(3);
                    try
                    {
                        // Console.WriteLine("3a");
                        pageResponseControl = (PageResultResponseControl)searchResponse.Controls[0];
                        // Console.WriteLine("3b");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Paging Error after 3: " + ex.Message);
                        break;
                    }
                    // Console.WriteLine(4);
                    if (pageResponseControl.Cookie.Length == 0)
                    {
                        // Console.WriteLine(5);
                        break;
                    }
                    // Console.WriteLine(6);
                    pageRequestControl.Cookie = pageResponseControl.Cookie;
                }
                // Console.WriteLine("Finding total count...");
                int totalCount = searchResponseList.Select(x => x.Entries.Count).ToList().Sum();
                // Console.WriteLine("Found " + totalCount + " users");
                foreach (SearchResponse response in searchResponseList)
                {
                    var searchEntries = response.Entries;

                    foreach (SearchResultEntry entry in searchEntries)
                    {
                        // Account Name
                        string accountName = entry.Attributes.Contains("sAMAccountName") ? (string)entry.Attributes["sAMAccountName"][0] : "";
                        accountName = accountName.Trim();
                        ldapInfo += $"- Account Name: {accountName}" + Environment.NewLine;

                        // Common Name
                        string commonName = entry.Attributes.Contains("cn") ? (string)entry.Attributes["cn"][0] : "";
                        commonName = commonName.Trim();
                        if (commonName != accountName)
                        {
                            ldapInfo += $"-- Common Name: {commonName}" + Environment.NewLine;
                        }

                        // User Principle Name
                        // userPrincipalName - Not really important
                            /*
                            string userPrincipalName = entry.Attributes.Contains("userPrincipalName") ? (string)entry.Attributes["userPrincipalName"][0] : "";
                            userPrincipalName = userPrincipalName.Trim();
                            if (userPrincipalName != accountName && userPrincipalName != "")
                            {
                                // Console.WriteLine("-- User Principle Name: " + userPrincipalName);
                            }
                            */
                            // memberOf
                        if (entry.Attributes.Contains("memberOf"))
                        {
                            foreach (var item in entry.Attributes["memberOf"])
                            {
                                if (item.GetType() == typeof(Byte[]))
                                {
                                    string itemStr = Encoding.Default.GetString((Byte[])item);
                                    if (itemStr.Contains("CN=Remote Desktop Users"))
                                    {
                                        ldapInfo += "-- " + "Member of the Remote Desktop Users Group (Can RDP in)".Recolor(Color.Orange) + Environment.NewLine;
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("-- Error - Unknown memberOf type - Bug Reelix: " + item.GetType());
                                }
                            }
                        }
                        // lastLogon
                        if (entry.Attributes.Contains("lastLogon"))
                        {
                            string value = (string)entry.Attributes["lastLogon"][0];
                            string lastLoggedIn = value == "0" ? "Never" : DateTime.FromFileTime(long.Parse(value)).ToString();
                            string lastLoggedInResponse = "-- Last Logged In: " + (lastLoggedIn == "Never" ? "Never" : lastLoggedIn.Recolor (Color.Orange));
                            ldapInfo += lastLoggedInResponse + Environment.NewLine;
                        }

                        // Description
                        string description = entry.Attributes.Contains("description") ? (string)entry.Attributes["description"][0] : "";
                        if (description != "")
                        {
                            // Default - Probably nothing interesting
                            if (accountName == "Administrator" || accountName == "Guest" || accountName == "krbtgt")
                            {
                                ldapInfo += $"-- Description: {description}" + Environment.NewLine;
                            }
                            else
                            {
                                // Custom description - Notify the user
                                ldapInfo += "-- " + ("Description: " + description).Recolor(Color.Orange) + Environment.NewLine;
                            }
                        }
                    }
                }
            }
            catch (DirectoryOperationException doex)
            {
                if (doex.Message.Contains("In order to perform this operation a successful bind must be completed on the connection."))
                {
                    username = username == null ? "null" : username;
                    password = password == null ? "null" : password;
                    ldapInfo += $"- Invalid Creds: {username} / {password}" + Environment.NewLine;
                }
                else
                {
                    Console.WriteLine("--> Unknown doex Error in LdapNew.GetInfo2 - Bug Reelix: " + doex.Message);
                }
            }
            catch (Exception ex)
            {
                if (ex.Message == "The supplied credential is invalid.")
                {
                    ldapInfo += "- Invalid Creds" + Environment.NewLine;
                }
                else if (ex.Message == "The LDAP server is unavailable.")
                {
                    ldapInfo = "- " + ex.Message;
                }
                else
                {
                    Console.WriteLine("--> Unknown ex Error in LdapNew.GetInfo2 - Bug Reelix: " + ex.Message);
                }
            }
            return ldapInfo;
        }
    }
}
