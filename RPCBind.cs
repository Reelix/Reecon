using Pastel;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class RPCBind
    {
        public static string GetInfo(string target, int port)
        {
            string toReturn = "";
            if (!General.IsInstalledOnLinux("rpcinfo"))
            {
                toReturn = "- " + "Error: Cannot find rpcinfo - Unable to enumerate - install rpcbind".Pastel(Color.Red);
            }
            else
            {
                List<string> processOutput = General.GetProcessOutput("rpcinfo", "-p " + target);
                foreach (string item in processOutput)
                {
                    toReturn += "- " + item + Environment.NewLine;
                }
            }
            return toReturn.Trim(Environment.NewLine.ToCharArray());
        }
    }
}
