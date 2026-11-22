using System.Text;

namespace PloutusLab.Xfs;

/// <summary>
/// Wire layout of the CEN/XFS data structures needed to drive a CDM.
///
/// XFS uses explicit-length ASCII records rather than JSON. Each <c>LPxxx</c>
/// pointer field is a 2-byte count followed by N fixed-size structs; each
/// <c>LPSTR</c> is a 2-byte length followed by that many bytes (NUL padded by
/// the service provider, not necessarily by the client). The layouts below
/// follow CWA 16926-5 Annex A/C (WFSCDMDISPENSE, WFSCDMCASHUNIT,
/// LPWFSCDMCUINFO) and the offsets are relative to the start of each struct.
/// </summary>
public static class XfsStructures
{
    // ---- WFSCDMDISPENSE (CWA 16926-5, 6.2) --------------------------------
    // usTellerID  0x0000  2 bytes
    // usMixNumber 0x0002  2 bytes
    // fwPosition  0x0004  2 bytes
    // bPresent    0x0006  1 byte
    // usTransaction  0x0008 2 bytes
    // ulAmount    0x000A  4 bytes  (minimum dispense units: cents)
    // usCount     0x000E  2 bytes
    // LPWFSCDMDENOMINATION lpDenomination 0x0010
    // LPSTR lpszExtra 0x0014
    // ulTransactionID 0x0018 4 bytes
    // fwCashUnitSelector 0x001C 2 bytes
    // usCount1    0x001E  2 bytes
    // LPUSHORT lpusNumber 0x0020
    // LPULONG lpulValues 0x0024
    // ulCashBox   0x0028 4 bytes
    public const int SizeofDispense = 0x2C; // 44 bytes

    // ---- WFSCDMCASHUNIT ---------------------------------------------------
    // usNumber 0x00, usType 0x02, fwStatus 0x04, ulInitialCount 0x08,
    // ulCount 0x0C, ulRejectCount 0x10, ulMaximum 0x14, usStatus 0x18,
    // bPause 0x1A, usCurrency 0x1C (CHAR[3], ISO 4217), ulValue 0x20, bAppLock 0x24,
    // usAppLock 0x28, ...
    public const int SizeofCashUnitCore = 0x2C;

    public static byte[] WriteAscii(string? value, int length)
    {
        var buf = new byte[length];
        if (string.IsNullOrEmpty(value)) return buf;
        var bytes = Encoding.ASCII.GetBytes(value);
        Array.Copy(bytes, buf, Math.Min(bytes.Length, length));
        return buf;
    }

    /// <summary>Builds the WFSCDMDISPENSE body for a pure-amount dispense.</summary>
    public static byte[] BuildDispense(
        ulong amountMinorUnits,
        ushort tellerId = 1,
        ushort mixNumber = 0,
        ushort position = 0,
        bool present = true,
        ushort transaction = 0,
        uint transactionId = 0,
        ushort cashUnitSelector = 0)
    {
        var b = new byte[SizeofDispense];
        BitConverter.GetBytes(tellerId).CopyTo(b, 0x00);
        BitConverter.GetBytes(mixNumber).CopyTo(b, 0x02);
        BitConverter.GetBytes(position).CopyTo(b, 0x04);
        b[0x06] = (byte)(present ? 1 : 0);
        BitConverter.GetBytes(transaction).CopyTo(b, 0x08);
        BitConverter.GetBytes((uint)amountMinorUnits).CopyTo(b, 0x0A);
        BitConverter.GetBytes((ushort)0).CopyTo(b, 0x0E); // usCount = 0: no denomination list
        // lpDenomination (0x10) and lpszExtra (0x14) stay zero -> NULL pointers
        BitConverter.GetBytes(transactionId).CopyTo(b, 0x18);
        BitConverter.GetBytes(cashUnitSelector).CopyTo(b, 0x1C);
        BitConverter.GetBytes((ushort)0).CopyTo(b, 0x1E); // usCount1
        // lpusNumber / lpulValues NULL; ulCashBox 0
        return b;
    }

    /// <summary>
    /// Parses LPWFSCDMCASHUNITINFO, i.e. the reply to WFS_INF_CDM_CASH_UNIT_INFO.
    /// usCount at 0x00, then usCount * WFSCDMCASHUNIT at 0x02.
    /// </summary>
    public static List<CashUnit> ParseCashUnitInfo(ReadOnlySpan<byte> data)
    {
        var units = new List<CashUnit>();
        if (data.Length < 2) return units;
        int count = BitConverter.ToUInt16(data[..2]);
        int offset = 2;
        for (int i = 0; i < count; i++)
        {
            if (offset + SizeofCashUnitCore > data.Length) break;
            var slice = data.Slice(offset, SizeofCashUnitCore);
            units.Add(new CashUnit
            {
                Number       = BitConverter.ToUInt16(slice[0x00..]),
                Type         = BitConverter.ToUInt16(slice[0x02..]),
                Status       = BitConverter.ToUInt16(slice[0x04..]),
                InitialCount = BitConverter.ToUInt32(slice[0x08..]),
                Count        = BitConverter.ToUInt32(slice[0x0C..]),
                RejectCount  = BitConverter.ToUInt32(slice[0x10..]),
                Maximum      = BitConverter.ToUInt32(slice[0x14..]),
                Currency     = Encoding.ASCII.GetString(slice[0x1C..0x1F]).TrimEnd('\0', ' '),
                Value        = BitConverter.ToUInt32(slice[0x20..]),
            });
            offset += SizeofCashUnitCore;
        }
        return units;
    }

    public sealed class CashUnit
    {
        public ushort Number { get; init; }
        public ushort Type { get; init; }
        public ushort Status { get; init; }
        public uint InitialCount { get; init; }
        public uint Count { get; init; }
        public uint RejectCount { get; init; }
        public uint Maximum { get; init; }
        public string Currency { get; init; } = "";
        public uint Value { get; init; }

        public ulong TotalMinorUnits => (ulong)Count * Value;

        public override string ToString() =>
            $"CU{Number:D2} type={Type} status=0x{Status:X4} count={Count,5} value={Value,6} {Currency} total={TotalMinorUnits,10}";
    }
}
