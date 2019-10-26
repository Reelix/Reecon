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
            }

            return ldapInfo;
        }
    }
}
