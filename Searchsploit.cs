using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace Reecon
{
    // https://github.com/offensive-security/exploitdb/blob/master/searchsploit
    class Searchsploit
    {
        public static void Search(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("SearchSploit Usage: reecon -searchsploit ProcessNameHere");
                Console.WriteLine("SearchSploit Usage: reecon -searchsploit -update");
                Console.WriteLine("SearchSploit Usage: reecon -searchsploit ExploitID -view");
                return;
            }

            string searchCommand = string.Join(" ", args);
            searchCommand = searchCommand.Remove(0, 14);
            Search(searchCommand);
        }

        private static void Search(string searchCommand)
        {
            WebClient wc = new WebClient();
            if (searchCommand.Contains("-update"))
            {
                Console.WriteLine("Updating...");
                if (File.Exists("files_exploits.csv"))
                {
                    Console.WriteLine("Existing exploit database found - Removing");
                }
                Console.WriteLine("Downloading update...");
                wc.DownloadFile("https://github.com/offensive-security/exploitdb/raw/master/files_exploits.csv", "files_exploits.csv");
                Console.WriteLine("Update complete!");
                return;
            }
            if (!File.Exists("files_exploits.csv"))
            {
                Console.WriteLine("Cannot find database - Please run -searchsploit -update");
                return;
            }

            List<DatabaseItem> database = Database.Parse("files_exploits.csv");

            if (searchCommand.Contains("-view"))
            {
                string[] searchItems = searchCommand.Split(' ');
                if (searchItems.Length == 2)
                {
                    string searchId = searchItems[0];
                    DatabaseItem theItem = database.FirstOrDefault(x => x.ID == searchId);
                    if (theItem != null)
                    {
                        Console.WriteLine("Exploit " + theItem.ID + ": " + theItem.Title);
                        string URL = "https://www.exploit-db.com/download/" + theItem.ID;
                        Console.WriteLine(URL);
                        wc.Headers[HttpRequestHeader.UserAgent] = "curl/7.55.1"; // Download restriction bypass
                        string downloadData = wc.DownloadString(URL);
                        Console.WriteLine(downloadData);
                    }
                    else
                    {
                        Console.WriteLine("Error - Invalid Item Id: " + searchId);
                    }
                }
                return;
            }

            List<DatabaseItem> items = database.Where(x => x.Title.ToLower().Contains(searchCommand.ToLower())).ToList(); // Case insensitive
            if (items.Count > 0)
            {
                items = items.OrderByDescending(x => x.ReleaseDate).ToList();

                int maxTitleLength = items.OrderByDescending(x => x.Title.Length).First().Title.Length;
                int maxAuthorLength = items.OrderByDescending(x => x.Author.Length).First().Author.Length;
                Console.WriteLine("".PadRight(47 + maxTitleLength + maxAuthorLength, '-'));
                Console.WriteLine("|  ID   |    Date    | " + "Title".PadRight(maxTitleLength, ' ') + "|  Type   | Platform | " + "Author".PadRight(maxAuthorLength, ' ') + "|");
                Console.WriteLine("".PadRight(47 + maxTitleLength + maxAuthorLength, '-'));
                foreach (DatabaseItem item in items)
                {
                    Console.WriteLine("| " + item.ID.PadRight(6, ' ') + "| " + item.ReleaseDate + " | " + item.Title.Trim('"').PadRight(maxTitleLength, ' ') +
                        "| " + item.Type.PadRight(8, ' ') + "| " + item.Platform.PadRight(9, ' ') + "| " + item.Author.Trim('"').PadRight(maxAuthorLength, ' ') + "|");
                }
                Console.WriteLine("".PadRight(47 + maxTitleLength + maxAuthorLength, '-'));
            }
            Console.WriteLine("Use -searchsploit id -view to view exploit");
        }

        private class Database
        {
            public static List<DatabaseItem> Parse(string dbFile)
            {
                List<string> dbItems = File.ReadAllLines(dbFile).ToList();
                List<DatabaseItem> database = new List<DatabaseItem>();
                foreach (string item in dbItems)
                {
                    string[] itemData = item.Split(',');
                    DatabaseItem dbItem = new DatabaseItem();
                    dbItem.ID = itemData[0];
                    dbItem.Path = itemData[1];
                    dbItem.Title = itemData[2];
                    dbItem.ReleaseDate = itemData[3];
                    dbItem.Author = itemData[4];
                    dbItem.Type = itemData[5];
                    dbItem.Platform = itemData[6];
                    database.Add(dbItem);
                }
                
                return database;
            }
        }

        private class DatabaseItem
        {
            public string ID;
            public string Path;
            public string Title;
            public string ReleaseDate;
            public string Author;
            public string Type;
            public string Platform;
        }
    }
}
