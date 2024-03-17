using System.Linq;

namespace Reecon
{
    internal class SMB_Protocol
    {
        public static byte[] negotiateProtoRequest()
        {
            byte[] netbios = new byte[]
            {
                0x00, // Message Type
                0x00, 0x00, 0x54 // Length - 84 (32 Header + 52 Negotiate = 84)
            };

            // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f
            byte[] smbHeader = new byte[]
            {
                // 32 bytes
                0xFF, 0x53, 0x4D, 0x42, // 'server_component': .SMB // Protocol
                0x72,                   // 'smb_command': - SMB_COM_NEGOTIATE (0x72) - Negotiate Protocol - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/32b5d4b7-d90b-483f-ad6a-003fd110f0ec
                0x00, 0x00, 0x00, 0x00, // 'nt_status' - Status (4 bytes): A 32-bit field used to communicate error messages from the server to the client.
                0x18,                   // 'flags' - Flags (1 byte): An 8-bit field of 1-bit flags describing various features in effect for the message.
                0x01, 0x28,             // 'flags2' - A 16-bit field of 1-bit flags that represent various features in effect for the message. Unspecified bits are reserved and MUST be zero.
                0x00, 0x00,             // 'process_id_high' - If set to a nonzero value, this field represents the high-order bytes of a process identifier (PID). It is combined with the PIDLow field below to form a full PID.
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 'signature' - This 8-byte field has three possible interpretations.
                0x00, 0x00,             // 'reserved'
                0x00, 0x00,             // 'tree_id'
                0x2F, 0x4B,             // 'process_id'
                0x00, 0x00,             // 'user_id' - A user identifier (UID).
                0xC5, 0x5E              // 'multiplex_id' - A multiplex identifier (MID).
            };

            byte[] negotiateProtoRequest = new byte[]
            {
                0x00, // 'word_count'
                0x31, 0x00, // 'byte_count' (49) + 3 in header = 52 Total
                
                // Requested Dialects
                0x02, // 'dialet_buffer_format'
                0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, // 'dialet_name': LANMAN1.0
                
                0x02, // 'dialet_buffer_format'
                0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, // 'dialet_name': LM1.2X002

                0x02, // 'dialet_buffer_format'
                0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00, // 'dialet_name3': NT LANMAN 1.0
                
                0x02, // 'dialet_buffer_format'
                0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00 // 'dialet_name4': NT LM 0.12
            };

            return netbios.Concat(smbHeader).Concat(negotiateProtoRequest).ToArray();
        }

        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/81e15dee-8fb6-4102-8644-7eaa7ded63f7
        public static byte[] sessionSetupAndxRequest()
        {
            byte[] netbios = new byte[] { 0x00, 0x00, 0x00, 0x63 };
            byte[] smbHeader = new byte[]
            {
                0xFF, 0x53, 0x4D, 0x42,
                0x73,
                0x00, 0x00, 0x00, 0x00,
                0x18,
                0x01, 0x20,
                0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x2F, 0x4B,
                0x00, 0x00,
                0xC5, 0x5E
            };

            byte[] setupAndxRequest = new byte[]
            {
                0x0D,
                0xFF,
                0x00,
                0x00, 0x00,
                0xDF, 0xFF,
                0x02, 0x00,
                0x01, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00,
                0x26, 0x00,
                0x00,
                0x2e, 0x00,
                0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x32, 0x30, 0x30, 0x30, 0x20, 0x32, 0x31, 0x39, 0x35, 0x00,
                0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x32, 0x30, 0x30, 0x30, 0x20, 0x35, 0x2e, 0x30, 0x00,
            };

            return netbios.Concat(smbHeader).Concat(setupAndxRequest).ToArray();
        }
    }
}
