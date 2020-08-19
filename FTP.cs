using FluentFTP;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace Reecon
{
    class FTP
    {
        public static string GetInfo(string ip)
        {
            string ftpUsername = "";
            string ftpLoginInfo = FTP.FtpLogin(ip, ftpUsername);
            if (ftpLoginInfo.Contains("Unable to login: This FTP server is anonymous only.") || ftpLoginInfo.Contains("Unable to login: USER: command requires a parameter") || ftpLoginInfo.Contains("Unable to login: Login with USER first.") || ftpLoginInfo.Contains("530 This FTP server is anonymous only."))
            {
                ftpUsername = "anonymous";
                ftpLoginInfo = FTP.FtpLogin(ip, ftpUsername, "");
            }
            if (ftpLoginInfo.Contains("Anonymous login allowed"))
            {
                string fileListInfo = FTP.TryListFiles(ip, true, "anonymous", "");
                if (fileListInfo.Contains("Not Implemented") || fileListInfo.Contains("invalid pasv_address"))
                {
                    fileListInfo = FTP.TryListFiles(ip, false, ftpUsername, "");
                }
                if (!fileListInfo.StartsWith(Environment.NewLine))
                {
                    fileListInfo = Environment.NewLine + fileListInfo;
                }
                ftpLoginInfo += fileListInfo;
            }
            return ftpLoginInfo.Trim(Environment.NewLine.ToCharArray());
        }

        public static string FtpLogin(string ftpServer, string username = "", string password = "")
        {
            string ftpLoginResult = "";
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
                string bannerMessage = response.BannerMessage.Trim();
                if (bannerMessage.StartsWith("220 "))
                {
                    bannerMessage = bannerMessage.Remove(0, 4);
                    if (bannerMessage.StartsWith("(") && bannerMessage.EndsWith(")"))
                    {
                        bannerMessage = bannerMessage.Remove(0, 1);
                        bannerMessage = bannerMessage.Remove(bannerMessage.Length - 1, 1);
                    }
                }

                if (!string.IsNullOrEmpty(bannerMessage))
                {
                    ftpLoginResult += Environment.NewLine + "- Version: " + bannerMessage;
                }
                if (response.WelcomeMessage.Trim() != "230 Login successful.")
                {
                    ftpLoginResult += Environment.NewLine + "- Welcome Message: " + response.WelcomeMessage.Trim();
                }
                if (response.SupportsHeaders)
                {
                    var headers = response.Headers;
                    if (headers != null && headers.Count != 0)
                    {
                        ftpLoginResult += Environment.NewLine + "- Headers (Contact Reelix): " + string.Join(",", headers.AllKeys);
                    }
                }
                if (string.IsNullOrEmpty(username) || username == "anonymous")
                {
                    ftpLoginResult += Environment.NewLine + "- Anonymous login allowed (Username: anonymous Password: *Leave Blank*)";
                }
                else
                {
                    Console.WriteLine("Woof!");
                }
                return ftpLoginResult;
            }
            catch (WebException ex)
            {
                if (ex.Message == "Unable to connect to the remote server")
                {
                    return Environment.NewLine + "- Unable to connect :<";
                }
                // Console.WriteLine("Some ex: " + ex.Message);
                FtpWebResponse response = (FtpWebResponse)ex.Response;
                ftpLoginResult += Environment.NewLine + "- Banner: " + response.BannerMessage.Trim();
                ftpLoginResult += Environment.NewLine + "- Status: " + response.StatusDescription.Trim();
                return ftpLoginResult;
            }

        }

        public static string TryListFiles(string ftpServer, bool usePassive, string username = "", string password = "")
        {
            string toReturn = "";
            FtpClient client = new FtpClient(ftpServer);
            client.Credentials = new NetworkCredential(username, password);
            client.Connect();
            /*
            Console.WriteLine("Test Type: " + client.ServerType.ToString());
            Console.WriteLine("Test Handler: " + client.ServerHandler);
            Console.WriteLine("Test OS: " + client.ServerOS);
            */
            toReturn += "-- OS Type: " + client.ServerOS + Environment.NewLine;
            FtpListItem[] itemList = client.GetListing("/", FtpListOption.AllFiles);
            if (itemList.Count() == 0)
            {
                toReturn += "- No Files Or Folders Found" + Environment.NewLine;
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
                    using (Stream stream = client.OpenRead(item.FullName))
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        while (!reader.EndOfStream)
                        {
                            string line = reader.ReadLine();
                            toReturn += "--- Text: " + line + Environment.NewLine;
                        }
                    }
                }
            }
            return toReturn;
        }
    }
}