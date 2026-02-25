using FluentFTP;
using FluentFTP.Client.BaseClient;
using FluentFTP.Exceptions;
// Note: FtpWebRequest isn't used due to https://github.com/dotnet/platform-compat/blob/master/docs/DE0003.md
using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;

namespace Reecon
{
    internal static class Ftp // File Transfer Protocol - Port 21
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            string ftpUsername = "";
            string ftpLoginInfo = "";
            try
            {
                ftpLoginInfo = FtpLogin(target, port, ftpUsername);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Rewrite Error: " + ex.Message);
                General.HandleUnknownException(ex);
            }

            ftpLoginInfo = ftpLoginInfo.Trim(Environment.NewLine.ToCharArray());
            return ("FTP", ftpLoginInfo);
        }


        public static string FtpLogin(string target, int port, string username = "", string password = "")
        {
            // Console.WriteLine("In FtpLogin2");
            string ftpLoginResult = "";
            if (username == "")
            {
                username = "anonymous";
            }

            NetworkCredential networkCredential = new NetworkCredential(username, password);
            FtpClient ftpClient = new FtpClient(target, networkCredential, port);
            ftpClient.Config.EncryptionMode = FtpEncryptionMode.Auto; // Port 990 for Implicit 
            ftpClient.ValidateCertificate += new FtpSslValidation(OnValidateCertificate);
            ftpClient.LegacyLogger = OnLogMessage;

            void OnLogMessage(FtpTraceLevel t, string loggerString)
            {
                if (loggerString.StartsWith("Response: 220 "))
                {
                    // Remove the logger-related stuff
                    string bannerMessage = loggerString.Remove(0, "Response: ".Length);
                    // logger messages end off with a time stamp in some weird format - [738959.568d]
                    bannerMessage = bannerMessage.Substring(0, bannerMessage.LastIndexOf('[') - 1);
                    ftpLoginResult += ParseBannerMessageResponse(bannerMessage) + Environment.NewLine;
                }
                /*
                 * For debugging
                else
                {
                    Console.WriteLine("Woof: " + loggerString);
                }
                */
            }

            void OnValidateCertificate(BaseFtpClient control, FtpSslValidationEventArgs e)
            {
                string issuer = e.Certificate.Issuer;
                string subject = e.Certificate.Subject;
                ftpLoginResult += "-- SSL Cert Issuer: " + issuer + Environment.NewLine;
                if (issuer != subject)
                {
                    ftpLoginResult += "-- SSL Cert Subject: " + subject + Environment.NewLine;
                }

                /*
                Console.WriteLine("Issuer: " + e.Certificate.Issuer);
                Console.WriteLine("Subject: " + e.Certificate.Subject);
                Console.WriteLine("Raw: " + e.Certificate.GetRawCertDataString());
                */
                // add logic to test if certificate is valid here
                e.Accept = true;
            }

            try
            {
                ftpClient.Connect();

                if (ftpClient.IsConnected)
                {
                    string portInfo = port == 21 ? "" : $":{port}";
                    ftpLoginResult += "- " + $"Anonymous login allowed -> ftp ftp://anonymous:@{target}{portInfo}".Recolor(Color.Orange) + Environment.NewLine;
                    // Console.WriteLine("FtpLogin2 - Connected");
                    // You can connect without being auth'd, but you can still read stuff even if so
                    ftpLoginResult += "-- OS: " + ftpClient.ServerOS + Environment.NewLine;
                    // Console.WriteLine("FtpLogin2 - Auth'd");
                    FtpListItem[] items = ftpClient.GetListing();
                    foreach (var item in items)
                    {
                        
                        // Ack
                        ftpLoginResult += "-- " + item.FullName + " (" + (item.Type == FtpObjectType.Directory ? "" : ("Size: " + item.Size + " -> ")) + "Perms: " + item.Chmod + " -> ";
                        if (item.Type == FtpObjectType.Directory)
                        {
                            ftpLoginResult += "Directory - Might want to look into this)" + Environment.NewLine;
                            FtpListItem[] innerItems = ftpClient.GetListing(item.FullName);
                            foreach (var innerItem in innerItems)
                            {
                                ftpLoginResult += "--- " + innerItem.FullName + " (Size: " + innerItem.Size + " -> Perms: " + innerItem.Chmod + " -> " + innerItem.Type + ")" + Environment.NewLine;
                                if (innerItem.Type == FtpObjectType.File && innerItem.Name.EndsWith(".txt") || innerItem.Name.EndsWith(".sh"))
                                {
                                    using Stream stream = ftpClient.OpenRead(innerItem.FullName);
                                    using StreamReader reader = new(stream);
                                    while (!reader.EndOfStream)
                                    {
                                        string line = reader.ReadLine() ?? "Line Null Error 2 in FTP.cs";
                                        ftpLoginResult += "---- Text: " + line + Environment.NewLine;
                                    }
                                }
                            }
                        }
                        else if (item.Type == FtpObjectType.File)
                        {
                            ftpLoginResult += "File)";
                        }

                        ftpLoginResult += Environment.NewLine;
                        if (item.Type == FtpObjectType.File && item.Name.EndsWith(".txt") || item.Name.EndsWith(".sh"))
                        {
                            using Stream stream = ftpClient.OpenRead(item.FullName);
                            using StreamReader reader = new(stream);
                            while (!reader.EndOfStream)
                            {
                                string line = reader.ReadLine() ?? "Line Null Error in FTP.cs";
                                ftpLoginResult += "--- Text: " + line + Environment.NewLine;
                            }
                        }
                    }
                }
            }
            catch (FtpAuthenticationException aex)
            {
                ftpLoginResult += "- OS: " + ftpClient.ServerOS + Environment.NewLine;
                string banner = ftpClient.LastReplies.First(x => x.Code == "220").Message;
                if (username == "anonymous" && aex.CompletionCode == "530")
                {
                    ftpLoginResult += "- No anonymous access permitted";
                }
                else
                {
                    ftpLoginResult += "- Ftp.cs - Unknown FtpAuthenticationException: " + aex.Message;
                    ;
                }
            }
            catch (Exception ex)
            {
                if (ftpClient.LastReplies == null)
                {
                    if (ex.Message ==
                        "Unable to read data from the transport connection: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.")
                    {
                        ftpLoginResult += "- Might've been an FTP Server, but it stopped responding." + Environment.NewLine;
                    }
                    else
                    {
                        ftpLoginResult += "- Weird FTP Server - Bug Reelix: " + ex.Message + Environment.NewLine;
                    }
                }
                else
                {
                    string banner = ftpClient.LastReplies.First(x => x.Code == "220").Message;
                    ftpLoginResult += "- Banner: " + banner + Environment.NewLine;
                    General.HandleUnknownException(ex);
                }
            }

            return ftpLoginResult;
        }

        private static string ParseBannerMessageResponse(string bannerMessage)
        {
            string toReturn = "";
            if (!string.IsNullOrEmpty(bannerMessage))
            {
                bannerMessage = bannerMessage.Trim();
                if (bannerMessage.StartsWith("220 "))
                {
                    bannerMessage = bannerMessage.Remove(0, 4);
                    if (bannerMessage.StartsWith("(") && bannerMessage.EndsWith(")"))
                    {
                        bannerMessage = bannerMessage.Remove(0, 1);
                        bannerMessage = bannerMessage.Remove(bannerMessage.Length - 1, 1);
                    }
                }

                toReturn += "- Banner: " + bannerMessage + Environment.NewLine;
                // All versions of ProFTPD 1.3.5 before 1.3.5a
                // All versions of ProFTPD 1.3.6 before 1.3.6rc1
                if (bannerMessage.Contains("ProFTPD "))
                {
                    if (bannerMessage.Contains("ProFTPD 1.3.5") || bannerMessage.Contains("ProFTPD 1.3.6"))
                    {
                        toReturn += "-- " + "Vulnerable ProFTPD Version Detected (Potential RCE) - CVE-2015-3306".Recolor(Color.Orange) + Environment.NewLine;
                    }
                    else
                    {
                        toReturn += "-- ProFTPD detected - Maybe vulnerable - Bug Reelix" + Environment.NewLine;
                    }
                }
            }

            return toReturn.Trim(Environment.NewLine.ToCharArray());
        }

        public static string TryListFiles(string ftpServer, int port, bool usePassive, string username = "", string password = "")
        {
            string toReturn = "";
            FtpClient client = new(ftpServer, username, password, port);
            client.Connect();
            /*
            Console.WriteLine("Test Type: " + client.ServerType.ToString());
            Console.WriteLine("Test Handler: " + client.ServerHandler);
            Console.WriteLine("Test OS: " + client.ServerOS);
            */
            toReturn += "-- OS Type: " + client.ServerOS + Environment.NewLine;
            FtpListItem[] itemList = client.GetListing("/", FtpListOption.AllFiles);
            if (itemList.Length == 0)
            {
                toReturn += "-- No Files Or Folders Found" + Environment.NewLine;
            }

            foreach (FtpListItem item in client.GetListing("/", FtpListOption.AllFiles))
            {
                string fileType = "";
                if (item.Type == FtpObjectType.Directory)
                {
                    fileType = " (Directory - Might want to look into this)";
                }
                else if (item.Type == FtpObjectType.File)
                {
                    fileType = " (File)";
                }
                else
                {
                    fileType = " (Fix Me!)";
                }

                toReturn += "-- " + item.Name + fileType + Environment.NewLine;
            }

            return toReturn;
        }
    }
}