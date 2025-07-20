namespace Reecon
{
    internal static class HTTPS // 443
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            string result = HTTP.GetInfoMain(target, port, true);
            return ("HTTPS", result);
        }
    }
}
