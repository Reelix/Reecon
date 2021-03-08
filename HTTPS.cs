using System;

namespace Reecon
{
    class HTTPS // 443
    {
        public static string GetInfo(string target, int port)
        {
            string result = HTTP.GetInfoMain(target, port, true);
            return result;
        }
    }
}
