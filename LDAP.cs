﻿using Pastel;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Drawing;
using System.Net;
using System.Text;

namespace Reecon
{
    class LDAP // Port 389
    {
        // Linux requires: https://packages.ubuntu.com/focal-updates/amd64/libldap-2.4-2/download
        // https://github.com/dotnet/runtime/issues/69456
        static string rootDseString = "";

        static int ldapPort = 0;
        public static string GetInfo(string ip, int port)
        {
            string returnInfo = "";
            ldapPort = port;
            returnInfo = LDAP.GetDefaultNamingContext(ip);
            returnInfo += LDAP.GetAccountInfo(ip, null, null);
            return returnInfo.Trim(Environment.NewLine.ToCharArray());
        }

        public static string GetDefaultNamingContext(string ip, bool raw = false)
        {
            string ldapInfo = string.Empty;
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ip);
            NetworkCredential creds = new NetworkCredential();
            //creds.UserName = "support\\ldap";
            creds.UserName = null;
            creds.Password = null;
            //creds.Password = original;
            LdapConnection connection = new LdapConnection(identifier, null)
            {
                AuthType = AuthType.Anonymous,
                SessionOptions =
                {
                    ProtocolVersion = 3
                }
            };
            SearchRequest searchRequest = new SearchRequest(null, "(objectclass=*)", SearchScope.Base);
            var response = connection.SendRequest(searchRequest) as SearchResponse;
            var searchEntries = response.Entries;
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
                    ldapInfo = $"- defaultNamingContext: {defaultNamingContext}" + Environment.NewLine;
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
            return ldapInfo;
        }

        public static string GetAccountInfo(string ip, string username = null, string password = null)
        {
            string ldapInfo = string.Empty;
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ip);
            NetworkCredential creds = new NetworkCredential();
            //creds.UserName = "support\\ldap";
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
            LdapConnection connection = new LdapConnection(identifier, creds)
            {
                AuthType = AuthType.Basic,
                SessionOptions =
                {
                    ProtocolVersion = 3
                }
            };
            try
            {
                connection.Bind();
                if (rootDseString == "")
                {
                    LDAP.GetDefaultNamingContext(ip);
                }
                SearchRequest searchRequest = new SearchRequest(rootDseString, "(objectclass=user)", SearchScope.Subtree);
                SearchResponse searchResponse = connection.SendRequest(searchRequest) as SearchResponse;
                var searchEntries = searchResponse.Entries;
                Console.WriteLine("Found " + searchEntries.Count + " users");
                foreach (SearchResultEntry entry in searchEntries)
                {
                    // Account Name
                    string accountName = entry.Attributes.Contains("sAMAccountName") ? (string)entry.Attributes["sAMAccountName"][0] : "";
                    accountName = accountName.Trim();
                    ldapInfo += "- Account Name: " + accountName + Environment.NewLine;

                    // Common Name
                    string commonName = entry.Attributes.Contains("cn") ? (string)entry.Attributes["cn"][0] : "";
                    commonName = commonName.Trim();
                    if (commonName != accountName)
                    {
                        ldapInfo += "-- Common Name: " + commonName + Environment.NewLine;
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
                                    ldapInfo += "-- " + "Member of the Remote Desktop Users Group (Can RDP in)".Pastel(Color.Orange) + Environment.NewLine;
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
                        string lastLoggedInResponse = "-- Last Logged In: " + (lastLoggedIn == "Never" ? "Never" : lastLoggedIn.Pastel(Color.Orange));
                        ldapInfo += lastLoggedInResponse + Environment.NewLine;
                    }

                    // Description
                    string description = entry.Attributes.Contains("description") ? (string)entry.Attributes["description"][0] : "";
                    if (description != "")
                    {
                        // Default - Probably nothing interesting
                        if (accountName == "Administrator" || accountName == "Guest" || accountName == "krbtgt")
                        {
                            ldapInfo += "-- Description: " + description + Environment.NewLine;
                        }
                        else
                        {
                            // Custom description - Notify the user
                            ldapInfo += "-- " + ("Description: " + description).Pastel(Color.Orange) + Environment.NewLine;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex.Message == "The supplied credential is invalid.")
                {
                    ldapInfo = "- Invalid Creds" + Environment.NewLine;
                }
                else if (ex.Message.Contains("In order to perform this operation a successful bind must be completed on the connection."))
                {
                    ldapInfo = "- Invalid Creds" + Environment.NewLine;
                }
                else if (ex.Message == "The LDAP server is unavailable.")
                {
                    ldapInfo = "- " + ex.Message;
                }
                else
                {
                    Console.WriteLine("--> Unknown Error in LdapNew.GetInfo2 - Bug Reelix: " + ex.Message);
                }
            }
            return ldapInfo;
            /*
            using (LdapConnection ldapConnection = new LdapConnection())
            {
                try
                {
                    ldapConnection.Connect(ip, ldapPort);
                    if (username != null && password != null)
                    {
                        ldapCreds.UserName = username;
                        ldapCreds.Password = password;
                        // May work to fix issue 65 - May not...
                        ldapConnection.SetOption(Native.LdapOption.LDAP_OPT_REFERRALS, IntPtr.Zero);
                        ldapConnection.Bind(Native.LdapAuthType.Negotiate, ldapCreds);
                    }
                    else
                    {
                        ldapConnection.Bind(Native.LdapAuthType.Simple, ldapCreds);
                    }
                }
                catch (Exception ex)
                {
                    if (ex.Message.Contains("SASL(-4)"))
                    {
                        // https://github.com/flamencist/ldap4net/issues/65
                        return "This unfortunately doesn't work on Linux in some cases";
                    }
                    else if (ex.Message.Contains("Invalid Credentials."))
                    {
                        if (username != null && password != null)
                        {
                            return "- Incorrect Credentails";
                        }
                        else
                        {
                            return "- No anonymous authentication allowed" + Environment.NewLine;
                        }
                    }
                    else
                    {
                        return "- Fatal Woof: " + ex.Message;
                    }
                }
                LdapEntry rootDse = new LdapEntry();
                if (rootDseString == "")
                {
                    rootDse = ldapConnection.GetRootDse();
                }
                IList<LdapEntry> searchEntries;
                try
                {
                    if (rootDseString != "")
                    {
                        searchEntries = ldapConnection.Search(rootDseString, "(objectclass=user)", scope: Native.LdapSearchScope.LDAP_SCOPE_SUB);
                    }
                    else if (rootDse.DirectoryAttributes.Contains("defaultNamingContext"))
                    {
                        string baseDn = rootDse.DirectoryAttributes["defaultNamingContext"].GetValue<string>();
                        searchEntries = ldapConnection.Search(baseDn, "(objectclass=user)", scope: Native.LdapSearchScope.LDAP_SCOPE_SUB);
                    }
                    else if (rootDse.DirectoryAttributes.Contains("namingContexts"))
                    {
                        string baseDn = rootDse.DirectoryAttributes["namingContexts"].GetValue<string>();
                        searchEntries = ldapConnection.Search(baseDn, "(objectclass=user)", scope: Native.LdapSearchScope.LDAP_SCOPE_SUB);
                    }
                    else
                    {
                        return "- rootDse has no defaultNamingContext / namingContexts. Keys: " + rootDse.DirectoryAttributes.Count;
                    }
                }
                catch (LdapException lex)
                {
                    // Non Auth
                    // Console.WriteLine("LDAP.GetAccountInfo LEX Error: " + lex + " - Bug Reelix!");
                    Console.WriteLine("LDAP.GetAccountInfo - Bug Reelix to fix this: " + lex.Message);
                    return "- No Anonymous Access Allowed";
                }
                catch (Exception ex)
                {
                    return $"Fatal Woof - Error in LDAP.GetAccountInfo - {ex.Message} - Bug Reelix!";
                }
                foreach (var result in searchEntries)
                {
                    string accountName = result.DirectoryAttributes.Contains("sAMAccountName") ? result.DirectoryAttributes["sAMAccountName"].GetValue<string>() : string.Empty;
                    if (accountName.Trim() == "System.Byte[]")
                    {
                        Console.WriteLine("Woof - Contact Reelix - Something broke in the LDAP Migration!!!");
                        //accountName = Encoding.UTF8.GetString((byte[])result.Attributes["samaccountname"][0]);
                    }
                    ldapInfo += " - Account Name: " + accountName + Environment.NewLine;
                    string commonName = result.DirectoryAttributes.Contains("cn") ? result.DirectoryAttributes["cn"].GetValue<string>() : string.Empty;
                    ldapInfo += " -- Common Name: " + commonName + Environment.NewLine;
                    if (result.DirectoryAttributes.Contains("userPrincipalName"))
                    {
                        ldapInfo += " -- userPrincipalName: " + result.DirectoryAttributes["userPrincipalName"].GetValue<string>() + Environment.NewLine;
                    }
                    if (result.DirectoryAttributes.Contains("lastLogon"))
                    {
                        string lastLoggedIn = result.DirectoryAttributes["lastLogon"].GetValue<string>();
                        if (lastLoggedIn != "0")
                        {
                            ldapInfo += " -- lastLogon: " + DateTime.FromFileTime(long.Parse(lastLoggedIn)) + Environment.NewLine;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Something broke with LDAP.GetAccountInfo.lastLogon :<");
                    }
                    if (result.DirectoryAttributes.Contains("description"))
                    {
                        string description = result.DirectoryAttributes["description"].GetValue<string>();
                        ldapInfo += " -- Description: " + description + Environment.NewLine;
                    }
                }
            }
            return ldapInfo.Trim(Environment.NewLine.ToCharArray());
            */
        }
    }
}
