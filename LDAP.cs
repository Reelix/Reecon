using LdapForNet;
using LdapForNet.Native;
using System;
using System.Collections.Generic;

namespace Reecon
{
    class LDAP // Port 389
    {
        // https://github.com/mono/mono/blob/master/mcs/class/System.DirectoryServices.Protocols/System.DirectoryServices.Protocols/SearchRequest.cs
        // Wow Mono - Just Wow...
        public static string GetInfo(string ip)
        {
            string returnInfo = "";
            returnInfo += LDAP.GetDefaultNamingContext(ip);
            returnInfo += LDAP.GetAccountInfo(ip);
            return returnInfo;
        }
        public static string GetDefaultNamingContext(string ip, bool raw = false)
        {
            string ldapInfo = string.Empty;
            using (LdapConnection ldapConnection = new LdapConnection())
            {
                ldapConnection.Connect(ip, 389);
                LdapCredential anonymousCredential = new LdapCredential();
                try
                {
                    ldapConnection.Bind(Native.LdapAuthType.Simple, anonymousCredential);
                }
                catch (LdapException le)
                {
                    return "- Connection Error: " + le.Message + Environment.NewLine;
                }
                catch (Exception ex)
                {
                    return "- Unknown Error: " + ex.Message + Environment.NewLine;
                }
                // ldapConnection.AuthType = AuthType.Anonymous;

                var searchEntries = ldapConnection.Search(null, "(objectclass=*)", scope: Native.LdapSearchScope.LDAP_SCOPE_BASE);
                // SearchRequest request = new SearchRequest(null, "(objectclass=*)", System.DirectoryServices.Protocols.SearchScope.Base, "defaultNamingContext");

                // SearchResponse result = (SearchResponse)ldapConnection.SendRequest(request);

                if (searchEntries.Count == 1)
                {
                    if (searchEntries[0].Attributes.ContainsKey("defaultNamingContext"))
                    {
                        string defaultNamingContext = searchEntries[0].Attributes["defaultNamingContext"][0].ToString();
                        if (raw)
                        {
                            ldapInfo = defaultNamingContext;
                        }
                        else
                        {
                            ldapInfo = $"- defaultNamingContext: {defaultNamingContext}" + Environment.NewLine;
                        }
                    }
                    else if (searchEntries[0].Attributes.ContainsKey("objectClass"))
                    {
                        string objectClass = searchEntries[0].Attributes["objectClass"][0].ToString();
                        ldapInfo = "- No defaultNamingContext, but we have an objectClass: " + objectClass + Environment.NewLine;
                    }
                    else
                    {
                        ldapInfo = "- Error: No defaultNamingContext! Keys: " + searchEntries[0].Attributes.Count + Environment.NewLine;
                        foreach (var item in searchEntries[0].Attributes)
                        {
                            ldapInfo += "- Found Key: " + item.Key + " with value " + item.Value + Environment.NewLine; ;
                        }
                    }
                }
                else

                {
                    ldapInfo = "- Multiple items found! Bug Reelix!" + Environment.NewLine;
                }
            }
            return ldapInfo;
        }

        public static string GetAccountInfo(string ip)
        {
            string ldapInfo = string.Empty;

            using (LdapConnection ldapConnection = new LdapConnection())
            {
                try
                {
                    ldapConnection.Connect(ip);
                    LdapCredential anonymousCredential = new LdapCredential();
                    ldapConnection.Bind(Native.LdapAuthType.Simple, anonymousCredential);
                }
                catch (Exception ex)
                {
                    return "- No anonymous authentication allowed" + Environment.NewLine;
                }
                var rootDse = ldapConnection.GetRootDse();
                IList<LdapEntry> searchEntries;
                try
                {
                    if (!rootDse.Attributes.ContainsKey("defaultNamingContext"))
                    {
                        return "- rootDse has no defaultNamingContext. Keys: " + rootDse.Attributes.Count;
                    }
                    searchEntries = ldapConnection.Search(rootDse.Attributes["defaultNamingContext"][0], "(objectclass=user)", scope: Native.LdapSearchScope.LDAP_SCOPE_SUB);
                }
                catch (LdapException)
                {
                    return "- No Anonymous Access Allowed";
                }
                catch (Exception)
                {
                    return ":<";
                }
                foreach (var result in searchEntries)
                {
                    string accountName = result.Attributes["sAMAccountName"].Count > 0 ? result.Attributes["sAMAccountName"][0].ToString() : string.Empty;
                    if (accountName.Trim() == "System.Byte[]")
                    {
                        Console.WriteLine("Woof - Contact Reelix - Something broke in the LDAP Migration!!!");
                        //accountName = Encoding.UTF8.GetString((byte[])result.Attributes["samaccountname"][0]);
                    }
                    ldapInfo += " - Account Name: " + accountName + Environment.NewLine;
                    string commonName = result.Attributes["cn"].Count > 0 ? (string)result.Attributes["cn"][0] : string.Empty;
                    ldapInfo += " -- Common Name: " + commonName + Environment.NewLine;
                    if (result.Attributes.ContainsKey("userPrincipalName"))
                    {
                        ldapInfo += " -- userPrincipalName: " + result.Attributes["userPrincipalName"][0] + Environment.NewLine;
                    }
                    if (result.Attributes["lastLogon"].Count == 1)
                    {
                        string lastLoggedIn = result.Attributes["lastLogon"][0];
                        if (lastLoggedIn != "0")
                        {
                            ldapInfo += " -- lastLogon: " + DateTime.FromFileTime(long.Parse(lastLoggedIn)) + Environment.NewLine;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Something broke with lastLogon :<");
                    }
                    if (result.Attributes.ContainsKey("description"))
                    {
                        string description = (string)result.Attributes["description"][0];
                        ldapInfo += " -- Description: " + result.Attributes["description"][0] + Environment.NewLine;
                    }
                }
            }
            return ldapInfo.Trim(Environment.NewLine.ToCharArray());
        }
    }
}
