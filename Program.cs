using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace NetworkMobileSettingsPatcher
{
    class Program
    {
        static void Main(string[] args)
        {
            string file = @"C:\Windows\SysNative\NetworkMobileSettings.dll";
            if (!File.Exists(file + ".bak"))
                File.Copy(file, file + ".bak");

            var proc = new Process();
            proc.StartInfo.FileName = "takeown.exe";
            proc.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            proc.StartInfo.Arguments = "/f " + file;
            proc.Start();
            proc.WaitForExit();

            proc = new Process();
            proc.StartInfo.FileName = "icacls.exe";
            proc.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            proc.StartInfo.Arguments = file + " /grant administrators:F";
            proc.Start();
            proc.WaitForExit();

            PatchFile(file);
        }

        static byte[] enablement = new byte[8] { 0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6 };
        static byte[] disablement = new byte[8] { 0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6 };

        static void PatchFile(string filepath)
        {
            using (var stream = File.Open(filepath, FileMode.Open, FileAccess.ReadWrite))
            {
                var position = FindPosition(stream, new byte[16] { 0xEB, 0x04, 0xA0, 0x52, 0x08, 0x25, 0x40, 0x29, 0x2A, 0x01, 0x08, 0x0A, 0x5F, 0x01, 0x0B, 0x6A });
                if (position != -1)
                {
                    position -= 0x50;
                    stream.Seek(position, SeekOrigin.Begin);
                    stream.Write(disablement, 0, disablement.Length);
                }

                stream.Seek(0, SeekOrigin.Begin);

                position = FindPosition(stream, new byte[16] { 0xEC, 0x04, 0xA0, 0x52, 0x08, 0x25, 0x40, 0x29, 0x2A, 0x01, 0x08, 0x0A, 0x5F, 0x01, 0x0C, 0x6A });
                if (position != -1)
                {
                    position -= 0x50;
                    stream.Seek(position, SeekOrigin.Begin);
                    stream.Write(disablement, 0, disablement.Length);
                }
            }

            var buffer = File.ReadAllBytes(filepath);
            CalculateChecksum(buffer);
            File.WriteAllBytes(filepath, buffer);
        }

        private static UInt32 CalculateChecksum(byte[] PEFile)
        {
            UInt32 Checksum = 0;
            UInt32 Hi;

            // Clear file checksum
            WriteUInt32(PEFile, GetChecksumOffset(PEFile), 0);

            for (UInt32 i = 0; i < ((UInt32)PEFile.Length & 0xfffffffe); i += 2)
            {
                Checksum += ReadUInt16(PEFile, i);
                Hi = Checksum >> 16;
                if (Hi != 0)
                {
                    Checksum = Hi + (Checksum & 0xFFFF);
                }
            }
            if ((PEFile.Length % 2) != 0)
            {
                Checksum += (UInt32)ReadUInt8(PEFile, (UInt32)PEFile.Length - 1);
                Hi = Checksum >> 16;
                if (Hi != 0)
                {
                    Checksum = Hi + (Checksum & 0xFFFF);
                }
            }
            Checksum += (UInt32)PEFile.Length;

            // Write file checksum
            WriteUInt32(PEFile, GetChecksumOffset(PEFile), Checksum);

            return Checksum;
        }

        private static UInt32 GetChecksumOffset(byte[] PEFile)
        {
            return ReadUInt32(PEFile, 0x3C) + +0x58;
        }

        internal static UInt32 ReadUInt32(byte[] ByteArray, UInt32 Offset)
        {
            // Assume CPU and FFU are both Little Endian
            return BitConverter.ToUInt32(ByteArray, (int)Offset);
        }

        internal static void WriteUInt32(byte[] ByteArray, UInt32 Offset, UInt32 Value)
        {
            System.Buffer.BlockCopy(BitConverter.GetBytes(Value), 0, ByteArray, (int)Offset, 4);
        }

        internal static UInt16 ReadUInt16(byte[] ByteArray, UInt32 Offset)
        {
            // Assume CPU and FFU are both Little Endian
            return BitConverter.ToUInt16(ByteArray, (int)Offset);
        }

        internal static void WriteUInt16(byte[] ByteArray, UInt32 Offset, UInt16 Value)
        {
            System.Buffer.BlockCopy(BitConverter.GetBytes(Value), 0, ByteArray, (int)Offset, 2);
        }

        internal static byte ReadUInt8(byte[] ByteArray, UInt32 Offset)
        {
            return ByteArray[Offset];
        }

        internal static void WriteUInt8(byte[] ByteArray, UInt32 Offset, byte Value)
        {
            ByteArray[Offset] = Value;
        }

        //
        // https://stackoverflow.com/questions/1471975/best-way-to-find-position-in-the-stream-where-given-byte-sequence-starts
        //
        public static long FindPosition(Stream stream, byte[] byteSequence)
        {
            if (byteSequence.Length > stream.Length)
                return -1;

            byte[] buffer = new byte[byteSequence.Length];

            BufferedStream bufStream = new BufferedStream(stream, byteSequence.Length);
            int i;
            while ((i = bufStream.Read(buffer, 0, byteSequence.Length)) == byteSequence.Length)
            {
                if (byteSequence.SequenceEqual(buffer))
                    return bufStream.Position - byteSequence.Length;
                else
                    bufStream.Position -= byteSequence.Length - PadLeftSequence(buffer, byteSequence);
            }

            return -1;
        }

        private static int PadLeftSequence(byte[] bytes, byte[] seqBytes)
        {
            int i = 1;
            while (i < bytes.Length)
            {
                int n = bytes.Length - i;
                byte[] aux1 = new byte[n];
                byte[] aux2 = new byte[n];
                Array.Copy(bytes, i, aux1, 0, n);
                Array.Copy(seqBytes, aux2, n);
                if (aux1.SequenceEqual(aux2))
                    return i;
                i++;
            }
            return i;
        }
    }
}
