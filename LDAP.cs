using LdapForNet;
using LdapForNet.Native;
using System;
using System.Collections.Generic;

namespace Reecon
{
    class LDAP // Port 389
    {
        static LdapCredential ldapCreds = new LdapCredential();
        static string rootDseString = "";

        static int ldapPort = 0;
        public static string GetInfo(string ip, int port)
        {
            string returnInfo = "";
            ldapPort = port;
            returnInfo += LDAP.GetDefaultNamingContext(ip);
            returnInfo += LDAP.GetAccountInfo(ip);
            return returnInfo.Trim(Environment.NewLine.ToCharArray());
        }

        public static string GetDefaultNamingContext(string ip, bool raw = false)
        {
            string ldapInfo = string.Empty;
            using (LdapConnection ldapConnection = new LdapConnection())
            {
                ldapConnection.Connect(ip, 389);
                try
                {
                    ldapConnection.Bind(Native.LdapAuthType.Simple, ldapCreds);
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
                    if (searchEntries[0].DirectoryAttributes.Contains("defaultNamingContext"))
                    {
                        string defaultNamingContext = searchEntries[0].DirectoryAttributes["defaultNamingContext"].GetValue<string>();
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
                    else if (searchEntries[0].DirectoryAttributes.Contains("objectClass"))
                    {
                        string objectClass = searchEntries[0].DirectoryAttributes["objectClass"].GetValue<string>();
                        ldapInfo = "- No defaultNamingContext, but we have an objectClass: " + objectClass + Environment.NewLine;
                    }
                    else
                    {
                        ldapInfo = "- Error: No defaultNamingContext! Keys: " + searchEntries[0].DirectoryAttributes.Count + Environment.NewLine;
                        foreach (var item in searchEntries[0].DirectoryAttributes)
                        {
                            ldapInfo += "- Found Key: " + item.Name + " with value " + item.GetValue<string>() + Environment.NewLine;
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

        public static string GetAccountInfo(string ip, string username = null, string password = null)
        {
            string ldapInfo = string.Empty;

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
                    Console.WriteLine("LDAP.GetAccountInfo LEX Error: " + lex + " - Bug Reelix!");
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
        }
    }
}