using FluentFTP;
using Pastel;
using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;

namespace Reecon
{
    class FTP // Port 21
    {
        public static string GetInfo(string target, int port)
        {
            string ftpUsername = "";
            string ftpLoginInfo;
            try
            {
                ftpLoginInfo = FTP.FtpLogin(target, ftpUsername);
            }
            catch (Exception ex)
            {
                return ("- Error: Unable to test FTP: " + ex.Message).Pastel(Color.Red);
            }
            if (ftpLoginInfo.Contains("Unable to login: This FTP server is anonymous only.") || ftpLoginInfo.Contains("Unable to login: USER: command requires a parameter") || ftpLoginInfo.Contains("Unable to login: Login with USER first.") || ftpLoginInfo.Contains("530 This FTP server is anonymous only."))
            {
                ftpUsername = "anonymous";
                ftpLoginInfo = FTP.FtpLogin(target, ftpUsername, "");
            }
            if (ftpLoginInfo.Contains("Anonymous login allowed"))
            {
                string fileListInfo = FTP.TryListFiles(target, port, true, "anonymous", "");
                if (fileListInfo.Contains("Not Implemented") || fileListInfo.Contains("invalid pasv_address"))
                {
                    fileListInfo = FTP.TryListFiles(target, port, false, ftpUsername, "");
                }
                ftpLoginInfo += fileListInfo;
            }
            string SSLCertInfo = FindFTPSSLCert(target);
            if (!string.IsNullOrEmpty(SSLCertInfo))
            {
                ftpLoginInfo += Environment.NewLine + SSLCertInfo;
            }
            return ftpLoginInfo.Trim(Environment.NewLine.ToCharArray());
        }

        public static string FtpLogin(string target, string username = "", string password = "")
        {
            string ftpLoginResult = "";
            string ftpServer = target;
            if (!ftpServer.StartsWith("ftp://"))
            {
                ftpServer = "ftp://" + ftpServer;
            }

            FtpWebRequest request = (FtpWebRequest)WebRequest.Create(ftpServer);
            request.Timeout = 5000;
            request.UseBinary = true; // Better for downloading files if we ever need
            request.UsePassive = true; // A better way to receive file listing
            request.KeepAlive = false; // Closes FTP after we're done
            request.Method = WebRequestMethods.Ftp.PrintWorkingDirectory;
            request.Credentials = new NetworkCredential(username, password);
            // FtpState state = new FtpState();
            // state.Request = request;
            // state.FileName = fileName;
            try
            {
                FtpWebResponse response = (FtpWebResponse)request.GetResponse();
                // If it gets here - It's connected!
                string bannerMessage = ParseBannerMessageResponse(response.BannerMessage);
                ftpLoginResult += bannerMessage + Environment.NewLine;
                if (response.WelcomeMessage.Trim() != "230 Login successful.")
                {
                    ftpLoginResult += "- Welcome Message: " + response.WelcomeMessage.Trim() + Environment.NewLine;
                }
                if (response.SupportsHeaders)
                {
                    WebHeaderCollection headers = response.Headers;
                    if (headers != null && headers.Count != 0)
                    {
                        ftpLoginResult += "- Headers (Contact Reelix): " + string.Join(",", headers.AllKeys) + Environment.NewLine;
                    }
                }
                if (string.IsNullOrEmpty(username) || username == "anonymous")
                {
                    ftpLoginResult += "- " + "Anonymous login allowed (Username: anonymous Password: *Leave Blank*)".Pastel(Color.Orange) + Environment.NewLine;
                }
                else
                {
                    Console.WriteLine("Woof!");
                }
                return ftpLoginResult.Trim(Environment.NewLine.ToCharArray());
            }
            catch (WebException ex)
            {
                if (ex.Message == "Unable to connect to the remote server")
                {
                    return Environment.NewLine + "- Unable to connect :<";
                }

                if (ex.Response != null)
                {
                    FtpWebResponse response = (FtpWebResponse)ex.Response;
                    if (response != null)
                    {
                        if (response.BannerMessage != null && response.StatusDescription != null)
                        {
                            string bannerMessage = ParseBannerMessageResponse(response.BannerMessage.Trim());
                            ftpLoginResult += bannerMessage + Environment.NewLine;
                            ftpLoginResult += "- Status: " + response.StatusDescription.Trim() + Environment.NewLine;
                        }
                        else
                        {
                            ftpLoginResult += "- Unable to get any FTP response: " + ex.Message + Environment.NewLine;
                            try
                            {
                                ftpLoginResult += "- Banner: " + General.BannerGrab(target, 21);
                            }
                            catch (Exception iex)
                            {
                                ftpLoginResult += "- Unable to get any banner response: " + iex.Message;
                            }
                        }
                    }
                    else
                    {
                        ftpLoginResult += "- Unable to get FTP response: " + ex.Message + Environment.NewLine;
                        try
                        {
                            ftpLoginResult += "- Banner: " + General.BannerGrab(target, 21);
                        }
                        catch (Exception iex)
                        {
                            ftpLoginResult += "- Unable to get any banner response: " + iex.Message;
                        }
                    }
                    return ftpLoginResult.Trim(Environment.NewLine.ToCharArray());
                }
                else
                {
                    ftpLoginResult += "- Unable to get any any response: " + ex.Message;
                    return ftpLoginResult;
                }
            }
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
                toReturn += "- Version: " + bannerMessage + Environment.NewLine;
                if (bannerMessage.Contains("ProFTPD 1.3.5"))
                {
                    toReturn += "-- " + "Vulnerable ProFTPD Version Detected (Potential RCE) - CVE-2015-3306".Pastel(Color.Orange) + Environment.NewLine;
                }
            }
            return toReturn.Trim(Environment.NewLine.ToCharArray());
        }

        public static string FindFTPSSLCert(string target)
        {
            string toReturn = "";
            try
            {
                if (!target.StartsWith("ftp://"))
                {
                    target = "ftp://" + target;
                }
                FtpClient client = new(target, "reelixwoof", "reelixwoof")
                {
                    EncryptionMode = FtpEncryptionMode.Explicit // Port 990 for Implicit
                };
                client.ValidateCertificate += new FtpSslValidation(OnValidateCertificate);
                client.Connect();

                void OnValidateCertificate(FtpClient control, FtpSslValidationEventArgs e)
                {
                    string issuer = e.Certificate.Issuer;
                    string subject = e.Certificate.Subject;
                    toReturn = "-- SSL Cert Issuer: " + issuer + Environment.NewLine;
                    if (issuer != subject)
                    {
                        toReturn += "-- SSL Cert Subject: " + subject;
                    }
                    /*
                    Console.WriteLine("Issuer: " + e.Certificate.Issuer);
                    Console.WriteLine("Subject: " + e.Certificate.Subject);
                    Console.WriteLine("Raw: " + e.Certificate.GetRawCertDataString());
                    */
                    // add logic to test if certificate is valid here
                    e.Accept = true;
                }
            }
            catch
            {
                // We don't really care
            }
            return toReturn.Trim(Environment.NewLine.ToCharArray());
        }

        public static string TryListFiles(string ftpServer, int port, bool usePassive, string username = "", string password = "")
        {
            string toReturn = "";
            FtpClient client = new(ftpServer, port, username, password);
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
                if (item.Type == FtpFileSystemObjectType.Directory)
                {
                    fileType = " (Directory - Might want to look into this)";
                }
                else if (item.Type == FtpFileSystemObjectType.File)
                {
                    fileType = " (File)";
                }
                else
                {
                    fileType = " (Fix Me!)";
                }
                toReturn += "-- " + item.Name + fileType + Environment.NewLine;
                if (item.Type == FtpFileSystemObjectType.File && item.Name.EndsWith(".txt"))
                {
                    using Stream stream = client.OpenRead(item.FullName);
                    using StreamReader reader = new(stream);
                    while (!reader.EndOfStream)
                    {
                        string line = reader.ReadLine();
                        toReturn += "--- Text: " + line + Environment.NewLine;
                    }
                }
            }
            return toReturn;
        }
    }
}