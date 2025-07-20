using System;
using System.Drawing;
using Novell.Directory.Ldap;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    internal static class LDAP // Port 389 / 636 (LDAPS)
    {
        // Linux requires: https://packages.ubuntu.com/focal-updates/amd64/libldap-2.4-2/download
        private static LdapConnection? connection;

        // OID required to view deleted objects
        private const string LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417";
        
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
            int intPort = int.Parse(port); 
            // Standard user enumeration
            string accountInfo = LDAP.GetAccountInfo(ip, intPort, username, password);
            Console.WriteLine(accountInfo);
            if (!accountInfo.Contains("Invalid Credentials"))
            {
                // Get any deleted objects
                string deletedInfo = GetDeletedObjects(ip, intPort, username, password);
                if (!string.IsNullOrEmpty(deletedInfo))
                {
                    Console.WriteLine("- " + "Deleted Items Detected".Recolor(Color.Green));
                    Console.WriteLine(deletedInfo);
                }
            }
        }


        private static string GetAccountInfo(string ip, int port, string userName, string password)
        {
            return GetAccountInfoAsync(ip, port, userName, password).GetAwaiter().GetResult();
        }
        
        private static async Task<string> GetAccountInfoAsync(string ip, int port, string userName, string password)
        {
            StringBuilder result = new();
            string? userPrincipalName = null;
            // string allUsersSearchFilter = "(&(objectCategory=person)(objectClass=*))";
            string allUsersSearchFilter = "(&(objectCategory=person)(objectClass=user))";
            string[] attributesToReturn = ["sAMAccountName", "cn", "description", "lastLogon", "userPrincipalName", "memberOf", "distinguishedName", "objectCategory", "objectClass"];

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
                ILdapSearchResults? searchResults = await connection.SearchAsync(searchBase, LdapConnection.ScopeSub, allUsersSearchFilter, attributesToReturn, false, searchConstraints
                ).ConfigureAwait(false);
                
                await ProcessSearchResults(searchResults, result);
            }
            catch (LdapReferralException refEx)
            {
                string[] referralUrls = refEx.GetReferrals();
                if (referralUrls.Length > 0 && userPrincipalName != null)
                {
                    LdapUrl referralUrl = new LdapUrl(referralUrls[0]);
                    bool canResolve = false;
                    try
                    {
                        Dns.GetHostEntry(referralUrl.Host);
                        canResolve = true;
                    }
                    catch (SocketException sex)
                    {
                        if (sex.Message == "Name or service not known")
                        {
                            Console.WriteLine($"- Error: Cannot resolve {referralUrl.Host} - Are you missing a Hosts file entry?");
                        }
                        else
                        {
                            General.HandleUnknownException(sex);
                        }
                    }

                    if (canResolve)
                    {
                        referralConnection = new LdapConnection();
                        try
                        {
                            await referralConnection.ConnectAsync(referralUrl.Host, referralUrl.Port).ConfigureAwait(false);
                            await referralConnection.BindAsync(userPrincipalName, password).ConfigureAwait(false);
                            // Console.WriteLine($" -> Authentication successful on referral server: {referralUrl.Host}");

                            ILdapSearchResults referralSearchResults = await referralConnection.SearchAsync(referralUrl.GetDn(), LdapConnection.ScopeSub, allUsersSearchFilter,
                                attributesToReturn, false, (LdapSearchConstraints)null!
                            ).ConfigureAwait(false);

                            // Console.WriteLine("\n--- User List from Referral Server ---");
                            await ProcessSearchResults(referralSearchResults, result);
                        }
                        catch (Exception ex)
                        {
                            General.HandleUnknownException(ex);
                        }
                    }
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
                General.HandleUnknownException(ex);
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

        // --- Deleted Objects Query ---

        public static string GetDeletedObjects(string ip, int port, string userName, string password)
        {
            return GetDeletedObjectsAsync(ip, port, userName, password).GetAwaiter().GetResult();
        }

        private static async Task<string> GetDeletedObjectsAsync(string ip, int port, string userName, string password)
        {
            StringBuilder result = new();
            LdapConnection? ldapConnection = null;

            try
            {
                // 1. Connect and discover the search base.
                (ldapConnection, string? searchBase) = await ConnectAndDiscoverNamingContextAsync(ip, port);
                if (string.IsNullOrEmpty(searchBase))
                {
                    return "- Error: Could not discover Naming Context.";
                }

                // 2. Authenticate. Querying deleted objects requires credentials.
                string domainName = ConvertNamingContextToDomain(searchBase);
                string userPrincipalName = $"{userName}@{domainName}";
                await ldapConnection.BindAsync(userPrincipalName, password).ConfigureAwait(false);

                // 3. Define the Deleted Objects container DN.
                string deletedObjectsDN = "CN=Deleted Objects," + searchBase;

                // 4. Set up the LDAP Control (LDAP_SERVER_SHOW_DELETED_OID).
                // OID, Criticality=True, Value=null
                LdapControl showDeletedControl = new(LDAP_SERVER_SHOW_DELETED_OID, true, null);

                // Configure search constraints and add the control.
                LdapSearchConstraints searchConstraints = new();
                searchConstraints.SetControls(showDeletedControl);
                
                // 5. Define search parameters.
                string filter = "(isDeleted=TRUE)";
                string[] attributesToReturn = ["sAMAccountName", "distinguishedName", "isDeleted", "lastKnownParent", "name", "whenChanged", "objectClass"];

                // 6. Perform the search.
                ILdapSearchResults? searchResults = await ldapConnection.SearchAsync(
                    deletedObjectsDN,
                    LdapConnection.ScopeSub,
                    filter,
                    attributesToReturn,
                    false,
                    searchConstraints
                ).ConfigureAwait(false);

                // 7. Process the results.
                await ProcessDeletedObjectResults(searchResults, result);

            }
            catch (LdapException lex)
            {
                if (lex.ResultCode == LdapException.InvalidCredentials)
                {
                    return "- Invalid Credentials provided.";
                }
                else if (lex.ResultCode == LdapException.NoSuchObject)
                {
                    // This often happens if the AD Recycle Bin feature is not enabled
                    return "- Could not find 'CN=Deleted Objects'. The AD Recycle Bin feature might not be enabled on this domain.";
                }
                else if (lex.ResultCode == LdapException.InsufficientAccessRights)
                {
                    return "- Insufficient Access Rights to view Deleted Objects.";
                }
                else
                {
                    return $"LDAP Error querying deleted objects: {lex.Message} (Code: {lex.ResultCode})";
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\nLDAP.cs - Deleted Objects Query FAILED: {ex.Message}");
                General.HandleUnknownException(ex);
                Console.ResetColor();
                throw;
            }
            finally
            {
                if (ldapConnection != null && ldapConnection.Connected)
                {
                    ldapConnection.Disconnect();
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
            string fixedNamingContext = ConvertNamingContextToDomain(namingContext);
            return fixedNamingContext;
        }

        private static (LdapConnection Connection, string? NamingContext) ConnectAndDiscoverNamingContext(string server, int port)
        {
            return ConnectAndDiscoverNamingContextAsync(server, port).GetAwaiter().GetResult();
        }

        private static async Task<(LdapConnection Connection, string? NamingContext)> ConnectAndDiscoverNamingContextAsync(string server, int port)
        {
            connection = new LdapConnection();
            string namingContext;
            try
            {
                await connection.ConnectAsync(server, port).ConfigureAwait(false);
                namingContext = await DiscoverNamingContextAsync(connection).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                General.HandleUnknownException(ex);
                namingContext = "Unknown";
            }
            connection.Dispose();
            return (connection, namingContext);
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

        // Helper function to safely get an attribute value or return "N/A"
        private static string GetAttributeValue(LdapAttributeSet attributeSet, string attributeName)
        {
            return attributeSet.ContainsKey(attributeName) ? attributeSet.GetAttribute(attributeName).StringValue : "N/A";
        }
        
        // Helper function to get multi-valued attributes (like objectClass)
        private static string[] GetAttributeValues(LdapAttributeSet attributeSet, string attributeName)
        {
            if (attributeSet.ContainsKey(attributeName))
            {
                var attribute = attributeSet.GetAttribute(attributeName);
                return attribute.StringValueArray;
            }
            return [];
        }
        
          // Processes results for deleted objects (AD Recycle Bin)
        private static async Task ProcessDeletedObjectResults(ILdapSearchResults searchResults, StringBuilder output)
        {
            await foreach (LdapEntry entry in searchResults)
            {
                LdapAttributeSet attributeSet = entry.GetAttributeSet();

                // Skip the Deleted Objects container itself if it appears in results
                string dName = GetAttributeValue(attributeSet, "distinguishedName");
                if (dName.StartsWith("CN=Deleted Objects,", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string name = GetAttributeValue(attributeSet, "name");
                string sAMAccountName = GetAttributeValue(attributeSet, "sAMAccountName");
                string lastKnownParent = GetAttributeValue(attributeSet, "lastKnownParent");
                string isDeleted = GetAttributeValue(attributeSet, "isDeleted");
                string whenChanged = GetAttributeValue(attributeSet, "whenChanged"); // Often represents time of deletion
                string[] objectClasses = GetAttributeValues(attributeSet, "objectClass");

                output.AppendLine($"- Name: {name}");
                
                if (sAMAccountName != "N/A")
                {
                    output.AppendLine($"-- sAMAccountName: {sAMAccountName.Recolor(Color.Orange)}");
                }

                output.AppendLine($"-- DN: {dName}");
                output.AppendLine($"-- isDeleted: {isDeleted}");
                output.AppendLine($"-- Last Known Parent: {lastKnownParent.Recolor(Color.Orange)}");
                
                if (objectClasses.Length > 0)
                {
                    output.AppendLine($"-- Object Class: {string.Join(", ", objectClasses)}");
                }

                if (whenChanged != "N/A")
                {
                    // AD generalized time format: YYYYMMDDHHMMSS.0Z
                    try
                    {
                        DateTime deletionTime = DateTime.ParseExact(whenChanged, "yyyyMMddHHmmss.f'Z'", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal).ToLocalTime();
                        output.AppendLine($"-- Deleted At (whenChanged): {deletionTime:yyyy-MM-dd HH:mm:ss}");
                    }
                    catch (FormatException)
                    {
                        output.AppendLine($"-- Deleted At (whenChanged): {whenChanged} (Raw)");
                    }
                }
            }
        }

        
        // Currently this is for user enum specifically - Need to make it more generic later on
        private static async Task ProcessSearchResults(ILdapSearchResults searchResults, StringBuilder output)
        {
            await foreach (LdapEntry? entry in searchResults)
            {
                LdapAttributeSet attributeSet = entry.GetAttributeSet();
                string? accountName = attributeSet.ContainsKey("sAMAccountName") ? attributeSet.GetAttribute("sAMAccountName").StringValue : null;
                string? commonName = attributeSet.ContainsKey("cn") ? attributeSet.GetAttribute("cn").StringValue : null;

                string? description = attributeSet.ContainsKey("description") ? attributeSet.GetAttribute("description").StringValue : null;

                string? memberOf = attributeSet.ContainsKey("memberOf") ? attributeSet.GetAttribute("memberOf").StringValue : null; 
                string? dName = attributeSet.ContainsKey("distinguishedName") ? attributeSet.GetAttribute("distinguishedName").StringValue : null;
                string? lastLogonTimestamp = attributeSet.ContainsKey("lastLogin") ? attributeSet.GetAttribute("lastLogon").StringValue : null; // Note: This is not replicated, lastLogonTimestamp is better but needs conversion
                string? userPrincipalName = attributeSet.ContainsKey("userPrincipalName") ? attributeSet.GetAttribute("userPrincipalName").StringValue : null;
                string? objectCategory = attributeSet.ContainsKey("objectCategory") ? attributeSet.GetAttribute("objectCategory").StringValue : null;

                if (accountName != null)
                {
                    output.AppendLine("- User: " + accountName);
                }

                if (commonName != accountName && !string.IsNullOrEmpty(commonName))
                {
                    output.AppendLine("-- Common Name: " + commonName);
                    if (!string.IsNullOrEmpty(userPrincipalName))
                    {
                        output.AppendLine("-- userPrincipalName: " + userPrincipalName);
                    }
                }

                if (dName != null)
                {
                    output.AppendLine("-- DN: " + dName);
                }

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

                if (objectCategory != null)
                {
                    output.AppendLine("-- objectCategory: " + objectCategory);
                }
            }
            // output.AppendLine($"\nFound {entryCount} user accounts in this context.");
        }
    }
}