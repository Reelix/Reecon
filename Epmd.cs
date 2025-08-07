using System;
using System.Collections.Generic;

namespace Reecon;

internal static class Epmd // Erlang Port Mapper Daemon - 4369
{
    public static (string PortName, string PortData) GetInfo(string ip, int port)
    {
        // Need to test this with more than a single returned node, or other data as well
        
        // https://www.erlang.org/doc/apps/erts/erl_dist_protocol.html
        // Each request *_REQ is preceded by a 2 byte length field. Thus, the overall request format is as follows:
        // 
        // 2	    n
        // Length	Request
        // Table: NAMES_REQ (110)
        // 110 is technically decimal, but it gets converted
        int namesReq = 110;
        byte namesReqByt = (byte)namesReq;
        byte[] requestPayload = [0x00, 0x01, namesReqByt];
        List<byte[]> payload =
        [
            requestPayload
        ];
        
        // If you don't wait the 250ms, half the time it just returns the first 4 bytes
        byte[] bannerInfo = General.BannerGrabBytes(ip, port, payload);
        
        // Should be 4 + x - Can't be <= 4
        if (bannerInfo.Length <= 4)
        {
            Console.WriteLine("- EPMD.cs - Something went wrong - Bug Reelix :(");
            return ("EMPD", "- Borked (Bug Reelix)");
        }
        
        // The response for a NAMES_REQ is as follows:
        // 
        // 4	
        // EPMDPortNo	NodeInfo*
        byte[] epmdPortBytes = bannerInfo[0..4];
        
        // EPMD uses Big-Endian. If the system is Little-Endian, the the bytes need to be reversed before converting.
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(epmdPortBytes);
        }
        int epmdPort = BitConverter.ToInt32(epmdPortBytes, 0);
        int nodeInfoLength = bannerInfo.Length - 4;
        string nodeInfoString = System.Text.Encoding.ASCII.GetString(bannerInfo, 4, nodeInfoLength);
        if (string.IsNullOrEmpty(nodeInfoString))
        {
            nodeInfoString = "Empty (Something went wrong - Bug Reelix)";
        }
        string returnInfo = $"- {epmdPort} Port Node: {nodeInfoString}";
        return (PortName: "EPMD", returnInfo);
    }
}