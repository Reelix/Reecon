using System;

namespace Reecon
{
    class Imap // Internet Message Access Protocol - Generally Port 143
    {
        public static (string PortName, string PortData) GetInfo(string ip, int port)
        {
            string returnInfo;
            string bannerInfo = General.BannerGrab(ip, port);

            // * OK [CAPABILITY IMAP4rev1 UIDPLUS CHILDREN NAMESPACE THREAD=ORDEREDSUBJECT THREAD=REFERENCES SORT QUOTA IDLE ACL ACL2=UNION STARTTLS ENABLE UTF8=ACCEPT] Courier-IMAP ready. Copyright 1998-2018 Double Precision, Inc.  See COPYING for distribution information.

            // * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot ready.

            // Rare: * OK NS572126 EmailArchitect IMAP4 Service, Version: 2019.11.0.2.1 ready at Wed, 15 Jul 2020 00:49:19 -0700
            if (bannerInfo.StartsWith("* OK "))
            {
                bannerInfo = bannerInfo.Remove(0, 5);
                if (bannerInfo.Substring(0, 12) == "[CAPABILITY ")
                {
                    // It has capabilities!
                    string capabilities = bannerInfo.Remove(0, bannerInfo.IndexOf("[CAPABILITY ", StringComparison.Ordinal) + 12);
                    capabilities = capabilities.Substring(0, capabilities.IndexOf("] ", StringComparison.Ordinal));

                    bannerInfo = bannerInfo.Remove(0, bannerInfo.IndexOf("] ", StringComparison.Ordinal) + 2);
                    returnInfo = "- Version: " + bannerInfo + Environment.NewLine;
                    returnInfo += "- Capabilities: " + capabilities;

                }
                else
                {
                    returnInfo = "- Version: " + bannerInfo;
                }
                returnInfo += Environment.NewLine + "- Maybe you can use this to log into a relevant email account?";
            }
            else
            {
                return ("IMAP?", "- Non-IMAP Banner Detected: " + bannerInfo);
            }
            return ("IMAP", returnInfo);
        }
    }
}
