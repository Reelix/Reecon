using System;

namespace Reecon
{
    internal static class Recolor
    {
        public const string Yellow = "\u001b[38;5;228m"; // 226/227 are too bright - Either 228/229 - Not sure...
        public const string Green  = "\u001b[38;5;46m";
        public const string Orange = "\u001b[38;5;214m";
        public const string Red    = "\u001b[38;5;9m";
        public const string White  = "\u001b[97m";
    }
}

namespace Reecon.Color
{
    internal static class Extensions
    {
        public static string Recolor(this string? input, string startCode)
        {
            if (input == null) return "";
            return $"{startCode}{input}" + "\u001b[97m";
        }
    }
}