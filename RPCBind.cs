using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class RPCBind
    {
        public static string GetInfo(string target, string port)
        {
            string toReturn = "";
            List<string> processOutput = General.GetProcessOutput("rpcinfo", "-p " + target);
            foreach (string item in processOutput)
            {
                toReturn += "- " + item + Environment.NewLine;
            }
            return toReturn;
        }
    }
}
