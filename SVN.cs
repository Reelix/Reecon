using System;
using System.Collections.Generic;
using System.Linq;

namespace Reecon
{
    class SVN // 3690
    {
        public static string GetInfo(string ip, int port)
        {
            string toReturn = "";
            if (General.GetOS() == General.OS.Linux)
            {
                if (General.IsInstalledOnLinux("svn"))
                {
                    // svn info svn://ip - Anything super useful?
                    string processOutput = string.Join("|", General.GetProcessOutput("svn", "log svn://" + ip));
                    List<string> commitList = processOutput.Split(new[] { "------------------------------------------------------------------------" }, StringSplitOptions.None).ToList();
                    commitList.RemoveAll(string.IsNullOrEmpty);
                    foreach (string commit in commitList)
                    {
                        List<string> splitItems = commit.Split('|').ToList();
                        splitItems.RemoveAll(string.IsNullOrEmpty);
                        // 0 - Revision
                        // 1 - Name
                        // 2 - Date
                        // 3 - Lines (?)
                        // 4 - Comment
                        try
                        {
                            string commitRevision = splitItems[0].Trim();
                            int commitDiff = int.Parse(commitRevision.Replace("r", "")) - 1; // Indexes - How do they work!
                            string commitName = splitItems[1].Trim();
                            string commitDate = splitItems[2];
                            string commitLines = splitItems[3];
                            string commitComments = splitItems[4];
                            string commitInfo = "- Commit " + commitRevision + " by " + commitName + " - " + commitComments + " ( svn diff -r" + commitDiff + " svn://" + ip + " )";
                            toReturn += commitInfo + Environment.NewLine;
                        }
                        catch (Exception ex)
                        {
                            toReturn += "- Conversion Error: " + ex.Message + Environment.NewLine;
                        }
                    }
                    toReturn = toReturn.Trim(Environment.NewLine.ToCharArray());
                }
                else
                {
                    Console.WriteLine("svn is not installed - Skipping enumeration (You probably want to 'sudo apt install subversion')");
                }
            }
            else
            {
                Console.WriteLine("svn.GetInfo currently lacks Windows support. Bug Reelix.");
            }
            return toReturn;
        }
    }
}
