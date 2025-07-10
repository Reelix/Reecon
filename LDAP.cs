using System;
using System.Drawing;
using Novell.Directory.Ldap;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    internal static class LDAP // Port 389 / 636 (LDAPS)
    {
        // Linux requires: https://packages.ubuntu.com/focal-updates/amd64/libldap-2.4-2/download
        private static LdapConnection? connection;

        public static (string PortName, string PortData) GetInfo(string ip, int port)
        {
            string returnInfo = "";
            /*
            if (checkCanRun != null)
            {
                // https://github.com/dotnet/runtime/issues/69456
                return ("LDAP", checkCanRun);
            }
            */
            string? namingContext = ConnectAndDiscoverNamingContextAsync(ip, port).GetAwaiter().GetResult().NamingContext;
            returnInfo += "- " + namingContext + Environment.NewLine;

            // We're currently going to assume that getting additional info actually requires auth
            // If this changes, very changes with HTB/Haze
            // returnInfo += GetAccountInfo(ip, port, null);

            // And clean up before returning
            returnInfo = returnInfo.Trim(Environment.NewLine.ToCharArray());
            return ("LDAP", returnInfo.Trim(Environment.NewLine.ToCharArray()));
        }

        public static void Run(string[] args)
        {
            if (args.Length != 5)
            {
                Console.WriteLine($"LDAP Auth Enum:\t{General.ProgramName} -ldap IP port validUsername validPassword");
                return;
            }

            string ip = args[1];
            string port = args[2];
            if (!int.TryParse(port, out _))
            {
                Console.WriteLine($"Invalid Port: {port}");
                Console.WriteLine($"LDAP Auth Enum:\t{General.ProgramName} -ldap IP port validUsername validPassword");
                Console.ResetColor();
                return;
            }

            string username = args[3];
            string password = args[4];
            string accountInfo = LDAP.GetAccountInfo(ip, int.Parse(port), username, password);
            Console.WriteLine(accountInfo);
        }


        private static string GetAccountInfo(string ip, int port, string userName, string password)
        {
            return GetAccountInfoAsync(ip, port, userName, password).GetAwaiter().GetResult();
        }
        
        private static async Task<string> GetAccountInfoAsync(string ip, int port, string userName, string password)
        {
            StringBuilder result = new();
            string? userPrincipalName = null;
            string allUsersSearchFilter = "(&(objectCategory=person)(objectClass=user))";
            string[] attributesToReturn = ["sAMAccountName", "cn", "description", "lastLogon", "userPrincipalName", "memberOf", "distinguishedName"];

            LdapConnection? referralConnection = null;

            try
            {
                // 1. Connect anonymously and discover the domain's naming context (search base).
                // Console.WriteLine($"\nAttempting to connect to {ip}:{port}...");
                (connection, string? searchBase) = await ConnectAndDiscoverNamingContextAsync(ip, port);

                // Console.WriteLine($" -> Connection successful.");
                // Console.WriteLine($" -> Discovered Search Base: {searchBase}");
                // 2. Convert naming context to a domain and construct the User Principal Name (UPN).
                // Console.WriteLine("\nConstructing User Principal Name (UPN)...");
                string domainName = ConvertNamingContextToDomain(searchBase);
                userPrincipalName = $"{userName}@{domainName}";
                // Console.WriteLine($" -> Constructed UPN: {userPrincipalName}");

                // 3. Bind (authenticate) using the constructed UPN and the provided password.
                // Console.WriteLine("\nAttempting to bind with constructed UPN...");
                await connection.BindAsync(userPrincipalName, password).ConfigureAwait(false);
                // Console.WriteLine(" -> Authentication successful.");

                // 4. Search for all user accounts.
                LdapSearchConstraints searchConstraints = new LdapSearchConstraints { ReferralFollowing = false };
                // Console.WriteLine("\nSearching for all user accounts...");
                ILdapSearchResults? searchResults = await connection.SearchAsync(
                    searchBase, LdapConnection.ScopeSub, allUsersSearchFilter, attributesToReturn, false, searchConstraints
                ).ConfigureAwait(false);

                // Console.WriteLine("\n--- User List from Primary Server ---");
                await ProcessSearchResults(searchResults, result);
            }
            catch (LdapReferralException refEx)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                // Console.WriteLine("\nReferral received. Following manually...");

                string[] referralUrls = refEx.GetReferrals();
                if (referralUrls.Length > 0 && userPrincipalName != null)
                {
                    LdapUrl referralUrl = new LdapUrl(referralUrls[0]);
                    referralConnection = new LdapConnection();
                    await referralConnection.ConnectAsync(referralUrl.Host, referralUrl.Port).ConfigureAwait(false);
                    await referralConnection.BindAsync(userPrincipalName, password).ConfigureAwait(false);
                    // Console.WriteLine($" -> Authentication successful on referral server: {referralUrl.Host}");

                    ILdapSearchResults referralSearchResults = await referralConnection.SearchAsync(referralUrl.GetDn(), LdapConnection.ScopeSub, allUsersSearchFilter, attributesToReturn, false, (LdapSearchConstraints)null!
                    ).ConfigureAwait(false);

                    // Console.WriteLine("\n--- User List from Referral Server ---");
                    await ProcessSearchResults(referralSearchResults, result);
                }

                Console.ResetColor();
            }
            catch (LdapException lex)
            {
                if (lex.Message == "Invalid Credentials")
                {
                    return "- Invalid Credentials";
                }
                else
                {
                    return $"Unknown LdapExecption: {lex.Message}";
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\nLDAP.cs - OPERATION FAILED: {ex.Message}");
                Console.ResetColor();
                throw; // Re-throw the exception to be caught by the caller if needed.
            }
            finally
            {
                // Clean up - Disconnect from any servers
                if (connection != null && connection.Connected)
                {
                    connection.Disconnect();
                }

                if (referralConnection != null && referralConnection.Connected)
                {
                    referralConnection.Disconnect();
                }
            }
            return result.ToString();
        }

        /// <summary>
        /// Converts an LDAP naming context (e.g., "DC=voleur,DC=htb")
        /// into a standard DNS domain name (e.g., "voleur.htb").
        /// </summary>
        private static string ConvertNamingContextToDomain(string? namingContext)
        {
            return string.Join(".", namingContext?.Split(',')
                .Where(part => part.Trim().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                .Select(part => part.Trim().Substring(3)) ?? []);
        }

        public static string GetPlainDefaultNamingContext(string ip, int port)
        {
            string? namingContext = ConnectAndDiscoverNamingContext(ip, port).NamingContext;
            string fixedNamingContext =  ConvertNamingContextToDomain(namingContext);
            return fixedNamingContext;
        }

        private static (LdapConnection Connection, string? NamingContext) ConnectAndDiscoverNamingContext(string server, int port)
        {
            return ConnectAndDiscoverNamingContextAsync(server, port).GetAwaiter().GetResult();
        }

        private static async Task<(LdapConnection Connection, string? NamingContext)> ConnectAndDiscoverNamingContextAsync(string server, int port)
        {
            connection = new LdapConnection();
            try
            {
                await connection.ConnectAsync(server, port).ConfigureAwait(false);
                string namingContext = await DiscoverNamingContextAsync(connection).ConfigureAwait(false);
                return (connection, namingContext);
            }
            catch
            {
                connection.Dispose();
                throw;
            }
        }

        private static async Task<string> DiscoverNamingContextAsync(LdapConnection? conn)
        {
            if (conn != null)
            {
                ILdapSearchResults? searchResults = await conn.SearchAsync("", LdapConnection.ScopeBase, "(objectClass=*)", ["defaultNamingContext"], false).ConfigureAwait(false);
                await foreach (LdapEntry entry in searchResults)
                {
                    LdapAttributeSet attributeSet = entry.GetAttributeSet();
                    if (attributeSet.GetAttribute("defaultNamingContext") != null)
                    {
                        return attributeSet.GetAttribute("defaultNamingContext").StringValue;
                    }
                }
            }

            throw new LdapException("Could not find the 'defaultNamingContext' attribute in the Root DSE.");
        }

        // Currently this is for user enum specifically - Need to make it more generic later on
        private static async Task ProcessSearchResults(ILdapSearchResults searchResults, StringBuilder output)
        {
            await foreach (LdapEntry? entry in searchResults)
            {
                LdapAttributeSet attributeSet = entry.GetAttributeSet();
                string accountName = attributeSet.GetAttribute("sAMAccountName").StringValue;
                string commonName = attributeSet.GetAttribute("cn").StringValue;

                string? description = attributeSet.ContainsKey("description") ? attributeSet.GetAttribute("description").StringValue : null;

                string? memberOf = attributeSet.ContainsKey("memberOf") ? attributeSet.GetAttribute("memberOf").StringValue : null; 
                string dName = attributeSet.GetAttribute("distinguishedName").StringValue;
                string lastLogonTimestamp = attributeSet.GetAttribute("lastLogon").StringValue; // Note: This is not replicated, lastLogonTimestamp is better but needs conversion
                string? userPrincipalName = attributeSet.ContainsKey("userPrincipalName") ? attributeSet.GetAttribute("userPrincipalName").StringValue : null;

                output.AppendLine("- User: " + accountName);
                
                if (commonName != accountName && !string.IsNullOrEmpty(commonName))
                {
                    output.AppendLine("-- Common Name: " + commonName);
                    output.AppendLine("-- userPrincipalName: " + userPrincipalName);
                }
                
                output.AppendLine("-- DN: " + dName);

                if (!string.IsNullOrEmpty(description))
                {
                    bool isDefaultDesc = (accountName == "Administrator" && description.Contains("Built-in account for administering")) ||
                                         (accountName == "Guest" && description.Contains("Built-in account for guest access")) ||
                                         (accountName == "krbtgt" && description.Contains("Key Distribution Center Service Account"));

                    if (!isDefaultDesc)
                    {
                        // And highlight anything useful
                        output.AppendLine("-- " + ("Description: " + description).Recolor(Color.Orange));
                    }
                    else
                    {
                        output.AppendLine("-- Description: " + description);
                    }
                }
                
                if (memberOf != null && memberOf.Contains("CN=REMOTE DESKTOP USERS", StringComparison.InvariantCultureIgnoreCase))
                {
                    output.AppendLine("-- " + "Member of Remote Desktop Users Group (Can RDP)".Recolor(Color.Orange));
                }
                
                if (!string.IsNullOrEmpty(lastLogonTimestamp) && lastLogonTimestamp != "0")
                {
                    try
                    {
                        DateTime lastLogonTime = DateTime.FromFileTimeUtc(long.Parse(lastLogonTimestamp)).ToLocalTime();
                        // Highlight recent logins (Last 180 days)
                        // Previously last 90, but getting some from a little further back is useful as well
                        bool recent = (DateTime.Now - lastLogonTime).TotalDays <= 180;
                        string displayTime = lastLogonTime.ToString("yyyy-MM-dd HH:mm:ss");
                        output.AppendLine("-- Last Logon: " + (recent ? displayTime.Recolor(Color.Orange) : displayTime));
                    }
                    catch
                    {
                        output.AppendLine("-- Last Logon: (Error parsing timestamp: " + lastLogonTimestamp + ")");
                    }
                }
                else if (lastLogonTimestamp == "0")
                {
                    output.AppendLine("-- Last Logon: Never");
                }
            }
            // output.AppendLine($"\nFound {entryCount} user accounts in this context.");
        }
    }
}