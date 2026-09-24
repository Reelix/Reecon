using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    internal class MQTT
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            string toReturn = "";
            using (Socket mqttSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                // Doing multiple requests with lots of data, so give it some time  
                mqttSocket.ReceiveTimeout = 3000;
                mqttSocket.SendTimeout = 3000;
                try
                {
                    mqttSocket.Connect(target, port);

                    // Send CONNECT
                    List<byte> connectPacket = GetConnectPacket();
                    mqttSocket.Send(connectPacket.ToArray(), connectPacket.Count, 0);

                    // Send SUBSCRIBE
                    List<byte> subscribePacket = GetSubscribePacket();
                    mqttSocket.Send(subscribePacket.ToArray(), subscribePacket.Count, 0);

                    // Listen for 3 seconds, then disconnect
                    List<byte> receivedData = new List<byte>();
                    byte[] buffer = new byte[4096];

                    Stopwatch stopwatch = Stopwatch.StartNew();
                    const int totalListenTimeMs = 3000;

                    while (stopwatch.ElapsedMilliseconds < totalListenTimeMs)
                    {
                        // Dynamically adjust ReceiveTimeout so it doesn't wait longer than remaining time
                        int remainingTime = totalListenTimeMs - (int)stopwatch.ElapsedMilliseconds;
                        if (remainingTime <= 0) break;
                        mqttSocket.ReceiveTimeout = remainingTime;

                        try
                        {
                            int bytesRead = mqttSocket.Receive(buffer, 0, buffer.Length, SocketFlags.None);
                            if (bytesRead == 0)
                            {
                                // Server gracefully closed the connection
                                break;
                            }

                            // Append the incoming chunk
                            for (int i = 0; i < bytesRead; i++)
                            {
                                receivedData.Add(buffer[i]);
                            }
                        }
                        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                        {
                            // Timeout reached; 3 seconds elapsed with no more incoming data
                            break;
                        }
                    }

                    // 4. Send MQTT DISCONNECT packet: 0xE0 (Type 14), 0x00 (Remaining Length 0)
                    byte[] disconnectPacket = new byte[] { 0xe0, 0x00 };
                    mqttSocket.Send(disconnectPacket, disconnectPacket.Length, SocketFlags.None);

                    mqttSocket.Shutdown(SocketShutdown.Both);
                    mqttSocket.Close();

                    // 5. Inspect the output
                    toReturn = ParseMqttStream(receivedData.ToArray());
                    
                    // And return
                    return ("MQTT", toReturn.Trim(Environment.NewLine.ToCharArray()));
                }
                catch (Exception ex)
                {
                    return ("MQTT", $"Error in MQTT.cs - Bug Reelix - {ex.Message}");
                    // Something went wrong
                }
            }
        }

        // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718028
        private static List<byte> GetConnectPacket()
        {
            // 3.1 CONNECT – Client requests a connection to a Server
            List<byte> packetBytes = new List<byte>();

            // 3.1.1 - Fixed Header
            packetBytes.Add(0x10); // Packet Type (1 -> Connect / 0 -> Reserved) 
            packetBytes.Add(0x0c); // Remaining Length - 12 (10 Header + 2 Payload)

            // 3.1.2 - Variable header
            // 3.1.2.1 - Protocol Name
            packetBytes.Add(0x00); // Length MSB (0)
            packetBytes.Add(0x04); // Length LSB (4)
            packetBytes.Add(0x4d); // M
            packetBytes.Add(0x51); // Q
            packetBytes.Add(0x54); // T
            packetBytes.Add(0x54); // T

            // 3.1.2.2 - Protocol Level
            packetBytes.Add(0x04); // The value of the Protocol Level field for the version 3.1.1 of the protocol is 4 (0x04). 

            // 3.1.2.3 - Connect Flags
            /*
               An 8-bit bitfield controlling session and authentication behavior:
               Bit 7: User Name Flag (0 = No username)
               Bit 6: Password Flag (0 = No password)
               Bit 5: Will Retain (0)
               Bits 4–3: Will QoS (00)
               Bit 2: Will Flag (0)
               Bit 1: Clean Session (1)
               Bit 0: Reserved (must be 0)
               00000010 binary = 0x02.
             */
            packetBytes.Add(0x02);

            // Keep Alive - 0x003c = 60 seconds.
            packetBytes.Add(0x00);
            packetBytes.Add(0x3c);

            // 3.1.3 - Payload (2 Bytes)
            packetBytes.Add(0x00); // Client ID Length MSB
            packetBytes.Add(0x00); // Client ID Length LSB

            // And return
            return packetBytes;
        }

        public static List<byte> GetSubscribePacket()
        {
            List<byte> packetBytes = new List<byte>();

            // Fixed Header
            packetBytes.Add(0x82); // SUBSCRIBE
            packetBytes.Add(0x0f); // Remaining Length: 15 bytes

            // Packet ID
            packetBytes.Add(0x00);
            packetBytes.Add(0x01);

            // --- Subscription 1: "#" (All application topics) ---
            packetBytes.Add(0x00);
            packetBytes.Add(0x01);
            packetBytes.Add((byte)'#');
            packetBytes.Add(0x00); // QoS 0

            // --- Subscription 2: "$SYS/#" (All system topics) ---
            packetBytes.Add(0x00);
            packetBytes.Add(0x06);
            packetBytes.Add((byte)'$');
            packetBytes.Add((byte)'S');
            packetBytes.Add((byte)'Y');
            packetBytes.Add((byte)'S');
            packetBytes.Add((byte)'/');
            packetBytes.Add((byte)'#');
            packetBytes.Add(0x00); // QoS 0

            return packetBytes;
        }

        private static int ReadVariableByteLength(byte[] data, ref int offset)
        {
            int multiplier = 1;
            int value = 0;
            byte encodedByte;
            do
            {
                encodedByte = data[offset++];
                value += (encodedByte & 127) * multiplier;
                multiplier *= 128;
                if (multiplier > 128 * 128 * 128)
                    throw new Exception("Malformed Remaining Length");
            } while ((encodedByte & 128) != 0);

            return value;
        }

        public static string ParseMqttStream(byte[] stream)
        {
            string toReturn = "";
            int offset = 0;

            while (offset < stream.Length)
            {
                if (offset >= stream.Length) break;

                // Byte 1: Packet Type (high nibble) and flags (low nibble)
                byte header = stream[offset++];
                byte packetType = (byte)(header >> 4);
                byte flags = (byte)(header & 0x0F);
                byte qos = (byte)((flags >> 1) & 0x03);

                // Read Remaining Length
                int remainingLength = ReadVariableByteLength(stream, ref offset);
                int packetEnd = offset + remainingLength;

                if (packetEnd > stream.Length)
                {
                    // Incomplete packet in buffer (truncated read)
                    break;
                }

                switch (packetType)
                {
                    case 9: // SUBACK
                        // Typically 2 bytes packet ID + 1 or more return codes
                        // We can skip past it
                        offset = packetEnd;
                        break;

                    case 3: // PUBLISH
                        // 1. Topic Length (2 bytes, Big-Endian)
                        int topicLength = (stream[offset] << 8) | stream[offset + 1];
                        offset += 2;

                        // 2. Topic String
                        string topic = Encoding.UTF8.GetString(stream, offset, topicLength);
                        offset += topicLength;

                        // 3. Packet Identifier (Only present if QoS > 0)
                        if (qos > 0)
                        {
                            offset += 2; // Skip 2-byte Packet ID
                        }

                        // 4. Payload (Everything left up to packetEnd)
                        int payloadLength = packetEnd - offset;
                        string payload = string.Empty;
                        if (payloadLength > 0)
                        {
                            payload = Encoding.UTF8.GetString(stream, offset, payloadLength);
                        }

                        toReturn += $"{topic} --> {payload}" + Environment.NewLine;
                        offset = packetEnd;
                        break;

                    default:
                        // Skip any other unhandled packet types (e.g. PINGRESP = 13)
                        offset = packetEnd;
                        break;
                }
            }

            return toReturn;
        }
    }
}