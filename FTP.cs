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
            string fileListResult = "";
            if (!ftpServer.StartsWith("ftp://"))
            {
                ftpServer = "ftp://" + ftpServer;
            }
            FtpWebRequest request = (FtpWebRequest)WebRequest.Create(ftpServer);
            request.Timeout = 5000;
            request.UsePassive = usePassive; // A better way to receive file listing
            request.KeepAlive = false; // Closes FTP after we're done
            request.Method = WebRequestMethods.Ftp.ListDirectoryDetails;
            request.Credentials = new NetworkCredential(username, password);
            try
            {
                FtpWebResponse response = (FtpWebResponse)request.GetResponse();
                using (StreamReader myStreamReader = new StreamReader(response.GetResponseStream()))
                {
                    List<string> responseLines = myStreamReader.ReadToEnd().Trim().Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList().Where(x => !string.IsNullOrEmpty(x)).ToList();
                    if (responseLines.Count == 0)
                    {
                        fileListResult += "- No Files Or Folders Found";
                    }
                    else
                    {
                        fileListResult += "- File Listing: " + Environment.NewLine;
                        foreach (var file in responseLines)
                        {
                            fileListResult += "-- ";
                            if (!string.IsNullOrEmpty(file) && file[0] == 'd')
                            {
                                fileListResult += file + " (Directory) " + Environment.NewLine;
                            }
                            else
                            {
                                fileListResult += file + Environment.NewLine;
                                // If it has read permissions and it's one of few files there - Read it
                                if ((file.Contains("-rw-r--r--") || file.Contains("rw-rw-r--") || file.Contains("rw-rw-rw-")) && responseLines.Count <= 3)
                                {
                                    string fileName = file.Remove(0, file.LastIndexOf(' ') + 1);
                                    try
                                    {
                                        string fileContents = ReadFile(ftpServer, usePassive, username, password, fileName);
                                        fileListResult += fileContents + Environment.NewLine;
                                    }
                                    catch (Exception ex)
                                    {
                                        if (ex.Message.Trim() == "The operation has timed out.")
                                        {
                                            fileListResult += "--- Timed out reading file " + fileName + " - You might need to do so manually";
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return fileListResult;
            }
            catch (WebException wex)
            {
                try
                {
                    FtpWebResponse innerResponse = (FtpWebResponse)wex.Response;
                    try
                    {
                        string someVal = innerResponse.ContentType;
                    }
                    catch (NotImplementedException)
                    {
                        return "- Not Implemented";
                    }
                    if ((int)innerResponse.StatusCode == 500)
                    {
                        if (innerResponse.StatusDescription.Trim() == "500 OOPS: invalid pasv_address")
                        {
                            return "- Unable to list files: invalid pasv_address";
                        }
                        else
                        {
                            return "- Unable to list files for unknown reason: " + innerResponse.StatusDescription;
                        }
                    }
                }
                catch
                {
                    Console.WriteLine("TryListFiles wex parse error: " + wex.Message);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unknown TryListFiles Error: " + ex.Message);
                return ":(";
            }
            return ":(";
        }

        private static string ReadFile(string ftpServer, bool usePassive, string username, string password, string fileName)
        {
            string fileContents = "--- Contents of " + fileName + Environment.NewLine;

            FtpWebRequest request = (FtpWebRequest)WebRequest.Create(ftpServer + "/" + fileName);
            // request.UseBinary = true; // More reliable way of downloading files
            request.Timeout = 5000;
            request.UsePassive = usePassive;
            request.Credentials = new NetworkCredential(username, password);
            request.Method = WebRequestMethods.Ftp.DownloadFile;

            using (Stream stream = request.GetResponse().GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();
                    fileContents += "--- " + line + Environment.NewLine;
                }
            }
            return fileContents;
        }
    }
}