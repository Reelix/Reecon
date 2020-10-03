using System;
using System.Collections.Generic;
using System.Data;
using MySqlConnector;

namespace Reecon
{
    class MySQL
    {
        static MySqlConnection connection;
        // Port: 3306
        // https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt
        // https://svn.nmap.org/nmap/scripts/mysql-info.nse
        // --> https://svn.nmap.org/nmap/nselib/mysql.lua -> receiveGreeting
        public static string GetInfo(string target, int port)
        {
            string returnData = "";
            
            MySqlConnection connection = new MySqlConnection($"Server={target};Port={port};Database=;Uid=reelixuser123;Pwd=;");

            try
            {
                connection.Open();
                if (connection.ServerVersion != null)
                {
                    returnData += "- Version: " + connection.ServerVersion;
                }
                else
                {
                    returnData += "- Version: Unknown";
                }
            }
            catch (MySqlException ex)
            {
                // Access Denied (Incorrect password)
                if (ex.Number == 1045)
                {
                    string defaultCredsResult = TestDefaults(target, port);
                    return defaultCredsResult;
                }
                else if (ex.Number == 1130)
                {
                    // Not allowed
                    if (ex.Message.Contains("MariaDB"))
                    {
                        return "- MariaDB Server (No External Authentication)";
                    }
                    else
                    {
                        return "- Unknown MySQL Server - Bug Reelix";
                    }
                }
                else
                {
                    Console.WriteLine("Unknown MySQL Error: " + ex.Number + " -- " + ex.Message);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error type: " + ex.Message);
                if (ex.Message.Contains("ERR 1044"))
                {
                    if (connection.ServerVersion != null)
                    {
                        returnData = "- Version: " + connection.ServerVersion;
                    }
                    else
                    {
                        Console.WriteLine("It's null :<");
                    }
                }
                else if (ex.Message.Contains("ERR 1130"))
                {
                    returnData = "- Access Denied: " + ex.Message;
                }
                else
                {
                    returnData = "Unknown Connection Exception: " + ex.Message;
                }
            }
            finally
            {
                connection.Close();
            }
            return returnData;
            
        }
        
        // Currently requires the GIGANTIC MySQL.dll as well as a dozen other refs >_<
        public static string TestDefaults(string target, int port)
        {
            List<string> testDetails = new List<string>()
            {
                "root:mysql",
                "root:root",
                "root:chippc",
                "admin:admin",
                "root:",
                "root:nagiosxi",
                "root:usbw",
                "cloudera:cloudera",
                "root:cloudera",
                "root:moves",
                "moves:moves",
                "root:testpw",
                "root:p@ck3tf3nc3",
                "mcUser:medocheck123",
                "root:mktt",
                "root:123",
                "dbuser:123",
                "asteriskuser:amp109",
                "asteriskuser:eLaStIx.asteriskuser.2oo7",
                "root:raspberry",
                "root:openauditrootuserpassword",
                "root:vagrant",
                "root:123qweASD#"
            };
            int tried = 0;
            foreach (string toTest in testDetails)
            {
                string username = toTest.Split(':')[0];
                string password = toTest.Split(':')[1];
                string success = TestPassword(target, port, username, password);
                if (success == "true")
                {
                    // Wow o_O
                    string toReturn = "- Default Credentails Found: " + username + ":" + password + Environment.NewLine;
                    toReturn += $"-- mysql -h {target} -u {username} -p {password}";
                    return toReturn;
                }
                else if (success == "break")
                {
                    break;
                }
                tried++;
            }
            return "- No Default Credentails Found (Tried " + tried + " / " + testDetails.Count + " variations)";
        }

        private static string TestPassword(string target, int port, string username, string password)
        {
            string connectionString = $"Server={target};Port={port};Database=;Uid=" + username + ";Pwd=" + password + ";";
            connection = new MySqlConnection(connectionString);
            try
            {
                connection.Open();
                return "true";
            }
            catch (MySqlException ex)
            {
                if (ex.Number == 1045)
                {
                    return "";
                }
                // Correct creds - Inval
                else if (ex.Number == 1049)
                {
                    Console.WriteLine("Woof: " + ex.Message);
                    return "true";
                }
                else if (ex.Number == 1049)
                {
                    Console.WriteLine("Error whilst testing MySQL Passwords");
                    Console.WriteLine("Unknown MySQL Error: " + ex.Number + " -- " + ex.Message);
                    return "break";
                }
                return "break";
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return "break";
            }
        }
    }
}
