namespace Reecon
{
    internal static class Https // 443
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            string result = Http.GetInfoMain(target, port, true);
            return ("HTTPS", result);
        }
    }
}
