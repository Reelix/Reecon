using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Reecon
{
    // https://github.com/offensive-security/exploitdb/blob/master/searchsploit
    class Searchsploit
    {
        static string dbPath = Directory.GetCurrentDirectory() + @"/files_exploits.csv";
        static string updatePath = "https://gitlab.com/exploit-database/exploitdb/raw/main/files_exploits.csv";

        public static void Search(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("SearchSploit Usage: reecon -searchsploit ProcessNameHere / ExploitID");
                Console.WriteLine("SearchSploit Usage: reecon -searchsploit -update");
                return;
            }

            string searchCommand = string.Join(" ", args);
            searchCommand = searchCommand.Remove(0, 14);
            if (searchCommand.Contains("-update"))
            {
                Update();
            }
            else
            {
                string toSearch = args[1];
                if (int.TryParse(toSearch, out _))
                {
                    View(toSearch);
                }
                else
                {
                    Search(toSearch);
                }
            }
        }

        private static void Update()
        {
            Console.WriteLine("Updating...");
            if (File.Exists(dbPath))
            {
                Console.WriteLine("Existing exploit database found - Removing");
            }
            Console.WriteLine($"Downloading update from {updatePath}...");
            General.DownloadFile(updatePath, dbPath);
            Console.WriteLine("Update complete!");
            return;
        }

        private static void View(string exploitId)
        {
            List<DatabaseItem> database = Database.Parse(dbPath);
            DatabaseItem theItem = database.FirstOrDefault(x => x.ID == exploitId);
            if (theItem != null)
            {
                Console.WriteLine("Exploit " + theItem.ID + ": " + theItem.Title);
                string URL = "https://www.exploit-db.com/download/" + theItem.ID;
                Console.WriteLine(URL);
                string downloadData = Web.DownloadString(URL, UserAgent: "curl/7.55.1").Text; // Download restriction bypass
                Console.WriteLine(downloadData);
            }
            else
            {
                Console.WriteLine("Error - Invalid Item Id: " + exploitId);
            }
            return;
        }

        private static void Search(string searchCommand)
        {
            if (!File.Exists(dbPath))
            {
                Console.WriteLine("Cannot find database - Please run -searchsploit -update (Will create a files_exploits.csv file in your current folder)");
                return;
            }

            List<DatabaseItem> database = Database.Parse(dbPath);
            foreach (string searchItem in searchCommand.Split(' '))
            {
                database = database.Where(x => x.Title.ToLower().Contains(searchItem.ToLower())).ToList(); // Case insensitive
            }
            if (database.Count > 0)
            {
                database = database.OrderByDescending(x => x.ReleaseDate).ToList();

                int maxTitleLength = database.OrderByDescending(x => x.Title.Length).First().Title.Length;
                int maxAuthorLength = database.OrderByDescending(x => x.Author.Length).First().Author.Length;
                Console.WriteLine("".PadRight(47 + maxTitleLength + maxAuthorLength, '-'));
                Console.WriteLine("|  ID   |    Date    | " + "Title".PadRight(maxTitleLength, ' ') + "|  Type   | Platform | " + "Author".PadRight(maxAuthorLength, ' ') + "|");
                Console.WriteLine("".PadRight(47 + maxTitleLength + maxAuthorLength, '-'));
                foreach (DatabaseItem item in database)
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
                List<DatabaseItem> database = new();
                foreach (string item in dbItems)
                {
                    string[] itemData = item.Split(',');
                    DatabaseItem dbItem = new()
                    {
                        ID = itemData[0],
                        Path = itemData[1],
                        Title = itemData[2],
                        ReleaseDate = itemData[3],
                        Author = itemData[4],
                        Type = itemData[5],
                        Platform = itemData[6]
                    };
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
