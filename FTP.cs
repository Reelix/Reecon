using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ReeRecon
{
    // Mostly yoinked from https://www.dreamincode.net/forums/topic/35902-create-an-ftp-class-library-in-c%23/
    class FTP
    {
        string ftpLoginResult = "";
        #region Variables
        //Property Variables
        private string firstLine = string.Empty;
        private string _ftpServer = string.Empty;
        private string _ftpPath = ".";
        private string _ftpUsername = string.Empty;
        private string _ftpPassword = string.Empty;
        private int _ftpPort = 21;
        private bool _isLoggedIn = false;
        private bool _isBinary = false;
        private int _timeOut = 10;
        //Static variables
        private static int BUFFER_SIZE = 512;
        private static Encoding ASCII = Encoding.ASCII;
        //Misc Global variables
        private bool _doVerbose = true;
        private string statusMessage = string.Empty;
        private string result = string.Empty;
        private int bytes = 0;
        private int _statusCode = 0;
        private Byte[] buffer = new Byte[BUFFER_SIZE];
        private Socket ftpSocket = null;
        #endregion




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
            //create our ip address object
            IPAddress remoteAddress = null;
            //create our end point object
            IPEndPoint addrEndPoint = null;
            try
            {
                //create our ftp socket
                ftpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                //retrieve the server ip
                remoteAddress = Dns.GetHostEntry(_ftpServer).AddressList[0];
                //set the endpoint value
                addrEndPoint = new IPEndPoint(remoteAddress, _ftpPort);
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
                throw new Exception("Couldn't connect to remote server", ex);
            }
            //read the host response
            readResponse();
            //check for a status code of 220
            if (_statusCode != 220)
            {
                //failed so close the connection
                CloseConnection();
                //throw an exception
                throw new FtpException(result.Substring(4));
            }
            //execute the USER ftp command (sends the username)
            Execute("USER " + _ftpUsername);
            //check the returned status code
            if (_statusCode == 500 || _statusCode == 501)
            {
                // 500 USER: command requires a parameter
                // 501 'USER': Invalid number of parameters.
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
                if (_statusCode == 530)
                {
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
            //verbose the login message
            if (_doVerbose)
            {
                Console.WriteLine("Connected to " + _ftpServer, "FtpClient");
            }
            // Get the initial working directory
            Execute("PWD");
            if (_statusCode == 257)
            {
                ftpLoginResult += Environment.NewLine + result.Substring(4);
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
            Execute("LIST");

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
                statusMessage += ASCII.GetString(buffer, 0, bytes);
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
                if (firstLine == "")
                {
                    firstLine = message;
                    ftpLoginResult += "- Version: " + firstLine.Substring(4);
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
            Byte[] cmdBytes = Encoding.ASCII.GetBytes((msg + "\r\n").ToCharArray());
            //send the command to the host
            ftpSocket.Send(cmdBytes, cmdBytes.Length, 0);
            //read the returned response
            readResponse();
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

}
