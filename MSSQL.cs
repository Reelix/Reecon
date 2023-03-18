using MySqlConnector;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class MSSQL
    {
        public static string GetInfo(string target, int port)
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
            */

            // If `public` has `xp_dirtree`, then you can capture the hash
            // If `public` has `dm_os_file_exists`, then you can check what files exist
            return "";
}
}
}
