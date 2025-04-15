using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
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
            string? checkCanRun = CanLDAPRun();
            if (checkCanRun != null)
            {
                // https://github.com/dotnet/runtime/issues/69456
                return ("LDAP", checkCanRun);
            }
            returnInfo += "- " + LDAP.GetDefaultNamingContext(ip, port) + Environment.NewLine;

            // We're currently going to assume that getting additional info actually requires auth
            // If this changes, very changes with HTB/Haze
            // returnInfo += LDAP.GetAccountInfo(ip, port, null);

            // And clean up before returning
            returnInfo = returnInfo.Trim(Environment.NewLine.ToCharArray());
            return ("LDAP", returnInfo.Trim(Environment.NewLine.ToCharArray()));
        }

        public static string? CanLDAPRun()
        {
            string? toReturn = null;
            try
            {
                LdapConnection connection = new LdapConnection("");
                return null;
            }
            catch (TypeInitializationException tex)
            {
                try
                {
                    if (tex.InnerException != null)
                    {
                        throw tex.InnerException;
                    }
                    else
                    {
                        toReturn += "LDAP.cs - The tex.InnerException is null :(";
                        return toReturn;
                    }
                }
                catch (DllNotFoundException dex)
                {
                    if (dex.Message.StartsWith("Unable to load shared library '"))
                    {
                        string missingLib = dex.Message.Remove(0, dex.Message.IndexOf("Unable to load shared library '") + "Unable to load shared library '".Length);
                        missingLib = missingLib.Substring(0, missingLib.IndexOf('\''));
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

        public static string GetDefaultNamingContext(string ip, int port)
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
            SearchRequest searchRequest = new SearchRequest("", "(objectClass=computer)", SearchScope.Base, ["defaultNamingContext", "serverName"]);
            try
            {
                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                SearchResultEntryCollection searchEntries = searchResponse.Entries;

                if (searchResponse.Entries.Count > 0)
                {
                    SearchResultEntry entry = searchResponse.Entries[0];
                    if (entry != null && entry.Attributes != null)
                    {
                        if (entry.Attributes.Contains("defaultNamingContext") && entry.Attributes["defaultNamingContext"].Count > 0)
                        {
                            rootDseString = entry.Attributes["defaultNamingContext"][0].ToString() ?? "";
                        }
                        string serverName = entry.Attributes["serverName"][0].ToString() ?? ""; // Not used, but may be useful later
                        return rootDseString;
                    }
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


        public static string GetAccountInfo(string ip, int port, string? username = null, string? password = null)
        {
            string ldapInfo = string.Empty;
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ip, port);
            if (rootDseString == "")
            {
                // An anonymous user can get the DNC, but a user with the incorrect creds cannot
                // ... Yes - It's weird...
                rootDseString = LDAP.GetDefaultNamingContext(ip, port);
            }

            // 
            // CN=fs01,CN=Computers,DC=vintage,DC=htb
            NetworkCredential? creds = new NetworkCredential();
            if (username == null && password == null)
            {
                creds = null;
            }
            else
            {
                // Better format
                Console.WriteLine("Testing LDAP with: " + username + ":" + password);
                username = "CN=" + username + ",CN=Users," + rootDseString;
                creds.UserName = username;
                creds.Password = password;
            }
            LdapConnection connection = new LdapConnection(identifier, creds);


            if (port == 389)
            {
                connection.AuthType = AuthType.Basic;
            }
            else
            {
                // Kerberos Auth does not work
                connection.AuthType = AuthType.Negotiate;
                Console.WriteLine("LDAP SSL - This will probably break...");
                // Ignore invalid SSL Certs
                connection.SessionOptions.VerifyServerCertificate += (conn, cert) => { return true; };
                // 
                connection.SessionOptions.StartTransportLayerSecurity(null);
            }
            //required for searching on root of ldap directory https://github.com/dotnet/runtime/issues/64900
            // connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

            connection.SessionOptions.ProtocolVersion = 3;

            try
            {

                string userFilter = "(objectClass=user)";
                string[] userAttrs = { "sAMAccountName", "cn", "description", "lastLogon", "memberOf", "distinguishedName" };
                ldapInfo += PerformPagedSearch(connection, rootDseString, userFilter, userAttrs, ParseUserEntry);

                // This is for later - Auto LDAP Pwn stuff
                /*
                // --- Enumerate gMSAs and check permissions (ONLY IF AUTHENTICATED) ---
                if (boundSuccessfully && creds != null) // Reading Security Descriptors typically requires authentication
                {
                    ldapInfo += Environment.NewLine + "-- Enumerating gMSAs & Checking ReadPassword Permissions --" + Environment.NewLine;
                    string gmsaFilter = "(objectClass=msDS-GroupManagedServiceAccount)";
                    // Crucially include nTSecurityDescriptor
                    string[] gmsaAttrs = { "*" };
                    ldapInfo += PerformPagedSearch(connection, rootDseString, gmsaFilter, gmsaAttrs, ParseGMSAEntry);
                }
                else if (creds == null)
                {
                    ldapInfo += Environment.NewLine + "-- Skipping gMSA Permission Check (Requires Authentication) --" + Environment.NewLine;
                }
                */
            }
            catch (DirectoryOperationException doex)
            {
                if (doex.Message.Contains("In order to perform this operation a successful bind must be completed on the connection."))
                {
                    username = username ?? "null";
                    password = password ?? "null";
                    ldapInfo += $"- Invalid Creds: {username} / {password}" + Environment.NewLine;
                }
                else
                {
                    Console.WriteLine("--> Unknown doex Error in LdapNew.GetInfo2 - Bug Reelix: " + doex.Message);
                }
            }
            catch (LdapException lex)
            {
                string sem = lex.ServerErrorMessage;
                // https://ldapwiki.com/wiki/Wiki.jsp?page=Common%20Active%20Directory%20Bind%20Errors
                if (lex.Message == "The supplied credential is invalid.")
                {
                    // https://ldapwiki.com/wiki/Wiki.jsp?page=Common%20Active%20Directory%20Bind%20Errors
                    // This is a lie - "ERROR_LOGON_FAILURE" / "52e" can appear for invalid usernames as well
                    ldapInfo += "- Invalid Creds" + Environment.NewLine;
                }
                else
                {
                    ldapInfo += $"- Unknown LdapException in LDAP.cs - {lex.Message} ({lex.ServerErrorMessage})" + Environment.NewLine;
                }
            }
            catch (Exception ex)
            {
                string exType = ex.GetType().ToString();
                if (ex.Message == "The LDAP server is unavailable")
                {
                    ldapInfo = $"- {ex.Message} ({exType})";
                }
                else if (ex.Message == "A local error occurred ")
                {
                    ldapInfo = $"- A local error occurred. Not quite sure why :( ({exType})";
                }
                else
                {
                    ldapInfo = $"- Unknown Exception Error in LDAP.cs - Bug Reelix: {ex.Message} ({exType})";
                }
            }
            return ldapInfo;
        }

        // Helper function for performing paged searches
        private static string PerformPagedSearch(LdapConnection connection, string searchBase, string filter, string[] attributes, Func<SearchResultEntry, string> entryParser)
        {
            string results = "";
            int entryCount = 0;

            int pageSize = 100; // A reasonable page size
            PageResultRequestControl pageRequestControl = new PageResultRequestControl(pageSize);
            // SearchOptionsControl searchOptionsControl = new SearchOptionsControl(SearchOption.DomainScope); // Needed for nTSecurityDescriptor

            SearchRequest searchRequest = new SearchRequest(searchBase, filter, SearchScope.Subtree, attributes);
            searchRequest.Controls.Add(pageRequestControl);
            // searchRequest.Controls.Add(searchOptionsControl); // Add Security Descriptor flag


            while (true)
            {
                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                // Find the page response control if it exists
                PageResultResponseControl? pageResponseControl = null;
                foreach (DirectoryControl control in searchResponse.Controls)
                {
                    if (control is PageResultResponseControl theControl)
                    {
                        pageResponseControl = theControl;
                        break;
                    }
                }

                // Process the entries in the current page
                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    results += entryParser(entry);
                    entryCount++;
                }

                // If the server doesn't support paging or it's the last page
                if (pageResponseControl == null || pageResponseControl.Cookie.Length == 0)
                {
                    break;
                }

                // Set the cookie for the next page request
                pageRequestControl.Cookie = pageResponseControl.Cookie;
            }

            results = $"- Found {entryCount} entries matching filter '{filter}'" + Environment.NewLine + results;
            return results.ToString();
        }


        // Specific parser for User entries
        private static string ParseUserEntry(SearchResultEntry entry)
        {
            string ldapInfo = "";

            string accountName = GetAttributeValue(entry, "sAMAccountName");
            string commonName = GetAttributeValue(entry, "cn");
            string description = GetAttributeValue(entry, "description");
            string dName = GetAttributeValue(entry, "distinguishedName");
            string lastLogonTimestamp = GetAttributeValue(entry, "lastLogon"); // Note: This is not replicated, lastLogonTimestamp is better but needs conversion
            string userPrincipleName = GetAttributeValue(entry, "userPrincipleName");
            bool isRDPUser = false;

            ldapInfo += "- DN: " + dName + Environment.NewLine;
            ldapInfo += "- User: " + accountName + Environment.NewLine;
            if (commonName != accountName && !string.IsNullOrEmpty(commonName))
            {
                ldapInfo += "-- Common Name: " + commonName + Environment.NewLine;
                ldapInfo += "-- userPrincipleName: " + userPrincipleName + Environment.NewLine;
            }
            if (!string.IsNullOrEmpty(description))
            {
                // Get a list of some default descriptions
                bool isDefaultDesc = (accountName == "Administrator" && description.Contains("Built-in account for administering")) ||
                                     (accountName == "Guest" && description.Contains("Built-in account for guest access")) ||
                                     (accountName == "krbtgt" && description.Contains("Key Distribution Center Service Account"));

                if (!isDefaultDesc)
                {
                    // And highlight anything useful
                    ldapInfo += "-- " + ("Description: " + description).Recolor(Color.Orange) + Environment.NewLine;
                }
                else
                {
                    ldapInfo += "-- Description: " + description + Environment.NewLine;
                }
            }

            // Process memberOf for RDP group
            if (entry.Attributes.Contains("memberOf"))
            {
                foreach (object memberOfAttr in entry.Attributes["memberOf"])
                {
                    string? groupDn = (memberOfAttr is byte[] bytes) ? Encoding.UTF8.GetString(bytes) : memberOfAttr.ToString();
                    // Simple check - might need refinement based on domain structure
                    if (groupDn != null && groupDn.ToUpperInvariant().Contains("CN=REMOTE DESKTOP USERS"))
                    {
                        isRDPUser = true;
                        break; // Found it, no need to check further
                    }
                }
            }
            if (isRDPUser)
            {
                ldapInfo += "-- " + "Member of Remote Desktop Users Group (Can RDP)".Recolor(Color.Orange) + Environment.NewLine;
            }


            // Process lastLogon (Be aware of limitations)
            if (!string.IsNullOrEmpty(lastLogonTimestamp) && lastLogonTimestamp != "0")
            {
                try
                {
                    DateTime lastLogonTime = DateTime.FromFileTimeUtc(long.Parse(lastLogonTimestamp)).ToLocalTime();
                    // Highlight recent logins (Last 180 days)
                    // Previously last 90, but getting some from a little further back is useful as well
                    bool recent = (DateTime.Now - lastLogonTime).TotalDays <= 180;
                    string displayTime = lastLogonTime.ToString("yyyy-MM-dd HH:mm:ss");
                    ldapInfo += "-- Last Logon: " + (recent ? displayTime.Recolor(Color.Orange) : displayTime) + Environment.NewLine;
                }
                catch
                {
                    ldapInfo += "-- Last Logon: (Error parsing timestamp: " + lastLogonTimestamp + ")" + Environment.NewLine;
                }
            }
            else if (lastLogonTimestamp == "0")
            {
                ldapInfo += "-- Last Logon: Never" + Environment.NewLine;
            }


            return ldapInfo.ToString();
        }

        // Helper to safely get string attribute value
        private static string GetAttributeValue(SearchResultEntry entry, string attributeName)
        {
            if (entry.Attributes.Contains(attributeName) && entry.Attributes[attributeName].Count > 0)
            {
                object attrValue = entry.Attributes[attributeName][0];
                if (attrValue is byte[] bytes)
                {
                    // Attempt UTF8 decoding, fallback if needed
                    try
                    {
                        return Encoding.UTF8.GetString(bytes);
                    }
                    catch
                    {
                        // Fallback for binary data
                        return Convert.ToBase64String(bytes);
                    }
                }
                return attrValue.ToString() ?? "";
            }
            return string.Empty;
        }
    }
}
