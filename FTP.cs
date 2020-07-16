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
            finally
            {
                request = null;
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
            request.UseBinary = true; // Better for downloading files if we ever need
            request.UsePassive = usePassive; // A better way to receive file listing
            request.KeepAlive = false; // Closes FTP after we're done
            request.Method = WebRequestMethods.Ftp.ListDirectoryDetails;
            request.Credentials = new NetworkCredential(username, password);
            try
            {
                FtpWebResponse response = (FtpWebResponse)request.GetResponse();
                if (!usePassive)
                {
                    fileListResult += "- PASV mode FALSE" + Environment.NewLine;
                }
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
                                // If it has VERY specific permissions and it's the onle file there - Read it
                                if (file.Contains("-rw-r--r--") && responseLines.Count == 1)
                                {
                                    string fileName = file.Remove(0, file.LastIndexOf(' ') + 1);
                                    try
                                    {
                                        string fileContents = ReadFile(ftpServer, usePassive, username, password, fileName);
                                        fileListResult += fileContents + Environment.NewLine;
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine("Error: Cannot read file: " + ex.Message);
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
            request.Timeout = 5000;
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

    /*
    // Mostly yoinked from https://www.dreamincode.net/forums/topic/35902-create-an-ftp-class-library-in-c%23/
    public string FtpLogin(string ftpServer, string username = "", string password = "")
    {
        _ftpServer = ftpServer;
        _ftpPort = 21;
        if (username != "")
        {
            _ftpUsername = username;
        }
        //check if the connection is currently open
        if (_isLoggedIn)
        {
            //its open so we need to close it
            CloseConnection();
        }
        //message that we're connection to the server
        if (_doVerbose)
        {
            Console.WriteLine("Opening connection to " + _ftpServer, "FtpClient");
        }
        //create our end point object
        try
        {
            //create our ftp socket
            ftpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            ftpSocket.SendTimeout = 5000;
            ftpSocket.ReceiveTimeout = 5000;
            //retrieve the server ip
            IPAddress remoteAddress = Dns.GetHostEntry(_ftpServer).AddressList[0];
            //set the endpoint value
            IPEndPoint addrEndPoint = new IPEndPoint(remoteAddress, _ftpPort);
            //connect to the ftp server
            ftpSocket.Connect(addrEndPoint);
        }
        catch (Exception ex)
        {
            // since an error happened, we need to
            //close the connection and throw an exception
            if (ftpSocket != null && ftpSocket.Connected)
            {
                ftpSocket.Close();
            }
            ftpLoginResult += Environment.NewLine + "- Unable to connect: " + ex.Message;
            return ftpLoginResult;
            // throw new Exception("Couldn't connect to remote server", ex);
        }
        //read the host response
        try
        {
            readResponse();
        }
        catch (Exception ex)
        {
            LogOut();
            ftpLoginResult += Environment.NewLine + "- Cannot Read Response: " + ex.Message;
            return ftpLoginResult;
        }
        //check for a status code of 220
        if (_statusCode != 220)
        {
            //failed so close the connection
            CloseConnection();
            //throw an exception
            throw new FtpException(result.Substring(4));
        }
        if (_statusCode == 220)
        {
            // Version response
            ftpLoginResult += Environment.NewLine + "- Version: " + result.Substring(4);
        }
        //execute the USER ftp command (sends the username)
        try
        {
            Execute("USER " + _ftpUsername);
        }
        catch (Exception ex)
        {
            LogOut();
            ftpLoginResult += Environment.NewLine + "- Cannot Execute USER: " + ex.Message;
            return ftpLoginResult;
        }
        //check the returned status code
        if (_statusCode == 500 || _statusCode == 501 || _statusCode == 421)
        {
            // 500 USER: command requires a parameter
            // 501 'USER': Invalid number of parameters.
            // 421 Can't change directory to /var/ftp/ [/]
            LogOut();
            ftpLoginResult += Environment.NewLine + "- Unable to login: " + result.Substring(4);
            return ftpLoginResult;
        }
        else if (_statusCode == 530)
        {
            // 530 This is a private system - No anonymous login
            // 530 This FTP server is anonymous only.
            LogOut();
            ftpLoginResult += Environment.NewLine + "- Unable to login: " + result.Substring(4);
            return ftpLoginResult;
        }
        // Uncaught USER status code
        if (!(_statusCode == 331 || _statusCode == 230))
        {
            //not what we were looking for so
            //logout and throw an exception
            LogOut();
            throw new FtpException(result.Substring(4));
        }
        if (_statusCode != 230)
        {
            //execute the PASS ftp command (sends the password)
            Execute("PASS " + _ftpPassword);
            //check the returned status code
            if (_statusCode == 530 || _statusCode == 331 || _statusCode == 503)
            {
                // 503 Login with USER first.
                LogOut();
                ftpLoginResult += Environment.NewLine + "- Unable to login: " + result.Substring(4);
                return ftpLoginResult;
            }
            // Uncaught PASS status code
            if (!(_statusCode == 230 || _statusCode == 202))
            {
                //not what we were looking for so
                //logout and throw an exception
                LogOut();
                throw new FtpException(result.Substring(4));
            }
        }
        //we made it this far so we're logged in
        _isLoggedIn = true;
        if (_ftpUsername == "anonymous")
        {
            ftpLoginResult += Environment.NewLine + "- Anonymous login allowed";
        }
        //verbose the login message
        if (_doVerbose)
        {
            Console.WriteLine("Connected to " + _ftpServer, "FtpClient");
        }
        // Get the initial working directory
        Execute("PWD");
        if (_statusCode == 257)
        {
            ftpLoginResult += Environment.NewLine + "- Current Directory: " + result.Substring(4);
        }
        else
        {
            LogOut();
            ftpLoginResult += Environment.NewLine + "- Unable to get current working directory: " + result.Substring(4);
            return ftpLoginResult;
        }
        Execute("PASV");
        if (_statusCode != 227) //  227 Entering Passive Mode (90,130,70,73,100,40).
        {
            LogOut();
            ftpLoginResult += Environment.NewLine + "- Unable to enter PASV mode: " + result.Substring(4);
            return ftpLoginResult;
        }
        // LIST / NLST never returns anything here...
        // Execute("PASV");
        ftpLoginResult += Environment.NewLine + "- Directory Listing not yet supported - Use nmap";
        // Execute("LIST");
        LogOut();
        // ChangeWorkingDirectory(_ftpPath);
        return ftpLoginResult;
    }

    private void readResponse()
    {
        statusMessage = "";
        result = ParseHostResponse();
        if (_doVerbose)
        {
            Console.WriteLine("FTP Response: " + result);
        }
        _statusCode = int.Parse(result.Substring(0, 3));
    }

    private string ParseHostResponse()
    {
        while (true)
        {
            //retrieve the host response and convert it to
            //a byte array
            bytes = ftpSocket.Receive(buffer, buffer.Length, 0);
            //decode the byte array and set the
            //statusMessage to its value
            statusMessage += Encoding.ASCII.GetString(buffer, 0, bytes);
            //check the size of the byte array
            if (bytes < buffer.Length)
            {
                break;
            }
        }
        //split the host response
        string[] msg = statusMessage.Split('\n');
        //check the length of the response
        if (statusMessage.Length > 2)
        {
            statusMessage = msg[msg.Length - 2];
        }
        else
        {
            statusMessage = msg[0];
        }
        foreach (string message in msg)
        {
            if (_doVerbose)
            {
                Console.WriteLine("Received Message: " + message);
            }
        }
        //check for a space in the host response, if it exists return
        //the message to the client
        if (!statusMessage.Substring(3, 1).Equals(" ")) return ParseHostResponse();
        //check if the user selected verbose Debugging
        if (_doVerbose)
        {
            //loop through the message from the host
            for (int i = 0; i < msg.Length - 1; i++)
            {
                //write each line out to the window
                Console.Write(msg[i], "FtpClient");
            }
        }
        //return the message
        return statusMessage;
    }

    private void Execute(string msg)
    {
        if (_doVerbose)
        {
            Console.WriteLine("Received Message: " + msg);
        }
        // Console.WriteLine(msg, "FtpClient");
        //convert the command to a byte array

        Byte[] cmdBytes = Encoding.ASCII.GetBytes((msg + Environment.NewLine).ToCharArray());
        //send the command to the host
        ftpSocket.Send(cmdBytes, cmdBytes.Length, 0);
        //read the returned response
        if (msg == "LIST")
        {
            Console.WriteLine("FTP - In LIST");
            byte[] listBuffer = new byte[512];
            ftpSocket.Receive(listBuffer);
            Console.WriteLine("FTP - In LIST 2");
            // bytes = ftpSocket.Receive(buffer, buffer.Length, 0);
            // Console.WriteLine("LIST returned bytes: " + buffer);
        }
        else
        {
            readResponse();
        }
    }

    public void ChangeWorkingDirectory(string dirName)
    {
        //check to make sure a directory name was supplied
        if (dirName == null || dirName.Equals(".") || dirName.Length == 0)
        {
            //no directory was provided so throw an exception 
            //and break out of the method
            throw new FtpException("A directory name wasn't provided. Please provide one and try your request again.");
        }
        //before we can change the directory we need
        //to make sure the user is logged in
        if (!_isLoggedIn)
        {
            //FtpLogin();
            throw new FtpException("You need to log in before you can perform this operation");
        }
        //execute the CWD command = Change Working Directory
        Execute("CWD " + dirName);
        //check for a return status code of 250
        if (_statusCode != 250)
        {
            //operation failed, throw an exception
            throw new FtpException(result.Substring(4));
        }
        //execute the PWD command
        //Print Working Directory
        Execute("PWD");
        //check for a status code of 250
        if (_statusCode != 257)
        {
            //operation failed, throw an exception
            throw new FtpException(result.Substring(4));
        }
        // we made it this far so retrieve the
        //directory from the host response
        _ftpPath = statusMessage.Split('"')[1];

        Console.WriteLine("Current directory is " + _ftpPath, "FtpClient");
    }

    public void CloseConnection()
    {
        //display the closing message
        Console.WriteLine("Closing connection to " + _ftpServer, "FtpClient");
        //check to see if the connection is still active
        //if it is then execute the ftp quit command
        //which terminates the connection
        if (ftpSocket != null)
        {
            Execute("QUIT");
        }
        //log the user out
        LogOut();
    }

    private void LogOut()
    {
        //check to see if the sock is non existant
        if (ftpSocket != null)
        {
            //since its not we need to
            //close it and dispose of it
            ftpSocket.Close();
            ftpSocket = null;
        }
        //log the user out
        _isLoggedIn = false;
    }

}

public class FtpException : Exception
{
    public FtpException(string message) : base(message)
    {
        Console.WriteLine("FTP Error -> " + message);
    }
    public FtpException(string message, Exception innerException) : base(message, innerException)
    {
        Console.WriteLine("FTP Error -> " + message + " --- " + innerException);
    }
}
*/
