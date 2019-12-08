using System;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Text;

namespace Reecon
{
    class LDAP
    {
        public static string GetDefaultNamingContext(string ip)
        {
            string ldapInfo = string.Empty;
            using (LdapConnection ldapConnection = new LdapConnection(ip))
            {
                ldapConnection.AuthType = AuthType.Anonymous;

                SearchRequest request = new SearchRequest(null, "(objectclass=*)",
                      System.DirectoryServices.Protocols.SearchScope.Base, "defaultNamingContext");

                SearchResponse result = (SearchResponse)ldapConnection.SendRequest(request);

                if (result.Entries.Count == 1)
                {
                    string defaultNamingContext = result.Entries[0].Attributes["defaultNamingContext"][0].ToString();
                    ldapInfo = ldapInfo + Environment.NewLine + "- defaultNamingContext: " + defaultNamingContext;
                }
            }
            return ldapInfo;
        }

        public static string GetAccountInfo(string ip)
        {
            string ldapInfo = string.Empty;
            DirectoryEntry rootEntry = new DirectoryEntry("LDAP://" + ip)
            {
                AuthenticationType = AuthenticationTypes.Anonymous
            };
            DirectorySearcher searcher = new DirectorySearcher(rootEntry);
            var queryFormat = "(&(objectClass=user))";
            searcher.Filter = queryFormat;
            foreach (SearchResult result in searcher.FindAll())
            {
                string accountName = result.Properties["samaccountname"].Count > 0 ? result.Properties["samaccountname"][0].ToString() : string.Empty;
                if (accountName.Trim() == "System.Byte[]")
                {
                    accountName = Encoding.UTF8.GetString((byte[])result.Properties["samaccountname"][0]);
                }
                ldapInfo += Environment.NewLine + " - Account Name: " + accountName;
                string commonName = result.Properties["cn"].Count > 0 ? (string)result.Properties["cn"][0] : string.Empty;
                ldapInfo += Environment.NewLine + " -- Common Name: " + commonName;
                if (result.Properties["userPrincipleName"].Count > 0)
                {
                    ldapInfo += " -- userPrincipleName: " + result.Properties["userPrincipleName"][0];
                }
                if (result.Properties["lastLogon"].Count > 0)
                {
                    string lastLoggedIn = Encoding.UTF8.GetString((byte[])result.Properties["lastLogon"][0]);
                    if (lastLoggedIn != "0")
                    {
                        ldapInfo += Environment.NewLine + " -- lastLogon: " + lastLoggedIn;
                    }
                }
                if (result.Properties["description"].Count > 0)
                {
                    string description = (string)result.Properties["description"][0];
                    ldapInfo += Environment.NewLine + " -- Description: " + result.Properties["description"][0];
                }
                
            }

            return ldapInfo;
        }
    }
}
