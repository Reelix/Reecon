using MySqlConnector;
using System;
using System.Collections.Generic;
using System.Drawing;

namespace Reecon
{
    class MySQL // Port 3306
    {
        static MySqlConnection connection;
        // https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt
        // https://svn.nmap.org/nmap/scripts/mysql-info.nse
        // --> https://svn.nmap.org/nmap/nselib/mysql.lua -> receiveGreeting
        public static (string, string) GetInfo(string target, int port)
        {
            string returnData = "";

            string connectionString = $"Server ={target};Port={port};Database=;Uid=reelixuser123;Pwd=;";
            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
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
                    if (ex.ErrorCode == MySqlErrorCode.UnableToConnectToHost)
                    {
                        returnData += "- Error 1042 - Timeout :(";
                    }
                    // Access Denied (Incorrect password)
                    // 1698 -- Access denied for user 'reelixuser123'@'ip-10-9-11-118.eu-west-1.compute.internal'
                    else if (ex.ErrorCode == MySqlErrorCode.AccessDenied || ex.Number == 1698)
                    {
                        string defaultCredsResult = TestDefaults(target, port);
                        returnData += defaultCredsResult;
                    }
                    else if (ex.ErrorCode == MySqlErrorCode.HostNotPrivileged)
                    {
                        // Not allowed
                        if (ex.Message.Contains("MariaDB"))
                        {
                            return ("MySQL (MariaDB)", "- MariaDB Server (No External Authentication)");
                        }
                        else if (ex.Message.Contains("is not allowed to connect to this MySQL server"))
                        {
                            return ("MySQL", "- MySQL (No External Authentication)");
                        }
                        else
                        {
                            Console.WriteLine("MySQL.cs - Bug Reelix 3");
                            return ("MySQL?", "- Unknown SQL Server Type - Bug Reelix" + Environment.NewLine + "-- " + ex.Message);
                        }
                    }
                    // 1698
                    else
                    {
                        Console.WriteLine("MySQL.cs - Bug Reelix 4");
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
                            Console.WriteLine("MySQL.cs - Bug Reelix 5");
                            returnData = "- Version: " + connection.ServerVersion;
                        }
                        else
                        {
                            Console.WriteLine("MySQL.cs - Bug Reelix 6");
                            Console.WriteLine("It's null :<");
                        }
                    }
                    else if (ex.Message.Contains("ERR 1130"))
                    {
                        Console.WriteLine("MySQL.cs - Bug Reelix 7");
                        returnData = "- Access Denied: " + ex.Message;
                    }
                    else
                    {
                        Console.WriteLine("MySQL.cs - Bug Reelix 8");
                        returnData = "Unknown Connection Exception: " + ex.Message;
                    }
                }
                finally
                {
                    if (connection != null && connection.State == System.Data.ConnectionState.Open && connection.ServerVersion != null)
                    {
                        Console.WriteLine("Woooof");
                        Console.WriteLine(connection.ServerVersion);
                    }
                    if (connection != null && connection.State == System.Data.ConnectionState.Open)
                    {
                        connection.Close();
                    }
                }
                return ("MySQL", returnData);
            }
        }

        // Currently requires the GIGANTIC MySQL.dll as well as a dozen other refs >_<
        public static string TestDefaults(string target, int port)
        {
            List<string> testDetails = new()
            {
                "root:mysql",
                "root:root",
                "root:chippc",
                "admin:",
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
                "root:123qweASD#",
                "root:password"
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
                    string toReturn = "- " + $"Default Credentials Found: {username}:{password}".Recolor(Color.Orange) + Environment.NewLine;
                    
                    // Should be able to inline this - It's being weird though
                    if (port == 3306)
                    {
                        toReturn += $"-- mysql -h {target} -u {username} -p" + Environment.NewLine;
                    }
                    else
                    {
                        toReturn += $"-- mysql -h {target} -u {username} -P {port} -p" + Environment.NewLine;
                    }
                    toReturn += GetCreds();
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
            Console.WriteLine(connectionString);
            connection = new MySqlConnection(connectionString);
            try
            {
                connection.Open();
                return "true";
            }
            catch (MySqlException ex)
            {
                Console.WriteLine(ex.Message);
                if (connection.State == System.Data.ConnectionState.Open)
                {
                    Console.WriteLine("Wadda");
                }
                if (ex.ErrorCode == MySqlErrorCode.AccessDenied || ex.Number == 1698)
                {
                    return "";
                }
                // Correct creds - Inval
                else if (ex.ErrorCode == MySqlErrorCode.UnknownDatabase)
                {
                    Console.WriteLine("Error whilst testing MySQL Passwords");
                    Console.WriteLine("Unknown MySQL Error: " + ex.Number + " -- " + ex.Message);
                    return "break";
                }
                return "break";
            }
            catch (Exception ex)
            {
                Console.WriteLine("Woofles: " + ex);
                return "break";
            }
        }

        private static string GetCreds()
        {
            string creds = "";
            // It's open from when the creds were correct
            if (connection.State == System.Data.ConnectionState.Open)
            {
                string command = "SELECT User, authentication_string from mysql.user;";
                MySqlCommand cmd = new(command, connection);
                MySqlDataReader rdr = cmd.ExecuteReader();
                // TODO: Test when the user doesn't have access to the mysql.user table
                while (rdr.Read())
                {
                    string username = rdr[0].ToString();
                    string password = rdr[1].ToString() == "" ? "*BLANK*" : rdr[1].ToString();
                    creds += "--- Creds in mysql.user" + Environment.NewLine; 
                    creds += "--- " + $"{username}:{password}".Recolor(Color.Orange) + Environment.NewLine;
                }
                rdr.Close();
            }
            return creds;
        }
    }
}
