using System;
using System.Collections.Generic;
using System.Drawing;

namespace Reecon
{
    class RPCBind
    {
        public static (string, string) GetInfo(string target, int port)
        {
            // rpcinfo has no Port parameter - Weird...
            string toReturn = "";
            if (!General.IsInstalledOnLinux("rpcinfo"))
            {
                toReturn = "- " + "Error: Cannot find rpcinfo - Unable to enumerate - install rpcbind".Recolor(Color.Red);
            }
            else
            {
                List<string> processOutput = General.GetProcessOutput("rpcinfo", "-p " + target);
                foreach (string item in processOutput)
                {
                    toReturn += "- " + item + Environment.NewLine;
                }
            }
            toReturn = toReturn.Trim(Environment.NewLine.ToCharArray());
            return ("RPCBind", toReturn);
        }
    }
}
