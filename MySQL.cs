using System;
using System.Collections.Generic;
using MyRawClient; // AKA: MySQL.dll

namespace Reecon
{
    class MySQL
    {
        // Port: 3306
        public static string GetVersion(string ip)
        {
            string returnData = "";
            string connectionString = "Server=" + ip + ";Database=test;Uid=reelixuser123;Pwd=;";
            MyRawConnection connection = new MyRawConnection(connectionString);
            try
            {
                connection.Open();
                if (connection.ServerInfo.ServerVersion != null)
                {
                    returnData += "- Version: " + connection.ServerInfo.ServerVersion;
                }
                else
                {
                    returnData += "- Version: Unknown";
                }
            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("ERR 1044"))
                {
                    if (connection.ServerInfo.ServerVersion != null)
                    {
                        returnData = "- Version: " + connection.ServerInfo.ServerVersion;
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
        public static string TestDefaults(string ip)
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
                string success = TestPassword(ip, username, password);
                if (success == "true")
                {
                    // Wow o_O
                    Console.WriteLine("Creds Found: " + username + ":" + password);
                    Console.ReadLine();
                    Console.ReadLine();
                    return "- Default Credentails Found: " + username + ":" + password;
                }
                else if (success == "break")
                {
                    break;
                }
                tried++;
            }
            return "- No Default Credentails Found (Tried " + tried + " / " + testDetails.Count + " variations)";
        }

        private static string TestPassword(string ip, string username, string password)
        {
            string connectionString = "Server=" + ip + ";Database=test;Uid=" + username + ";Pwd=" + password + ";";
            MyRawConnection connection = new MyRawConnection(connectionString);
            try
            {
                connection.Open();
                return "true";
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return "break";
            }
        }
    }
}
