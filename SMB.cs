using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class SMB
    {
        public static string TestAnonymousAccess(string IP, string username = "", string password = "")
        {
            string toReturn = "";
            try
            {
                using (SMB_NetworkShareAccesser.Access(IP, username, password))
                {
                    SMB_GetNetShares getNetShares = new SMB_GetNetShares();
                    List<SMB_GetNetShares.SHARE_INFO_1> shareInfoList = getNetShares.EnumNetShares(IP).ToList();
                    foreach (var shareInfo in shareInfoList)
                    {
                        toReturn += Environment.NewLine + " - Anonymous Share: " + shareInfo.shi1_netname + " - " + shareInfo.shi1_type + " - " + shareInfo.shi1_remark;
                    }
                }
            }
            catch (Exception ex)
            {
                toReturn += Environment.NewLine + " - Unable to Anonymous connect: " + ex.Message;
            }
            return toReturn;
        }
    }
}
