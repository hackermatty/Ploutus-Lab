using System.Net.Sockets;
using System.Text;

namespace PloutusLab.Xfs;

/// <summary>
/// Which XFS entry point a message belongs to.
///
/// This matters more than it looks: CEN/XFS gives info commands and execute
/// commands the *same* numeric window (CDM: both start at service offset + 1),
/// and the service provider tells them apart by the API that was called -
/// WFSGetInfo versus WFSExecute - not by the number alone. A faithful frame
/// therefore has to carry the API as well as the command, otherwise
/// WFS_INF_CDM_CASH_UNIT_INFO (303) and WFS_CMD_CDM_PRESENT (303) are
/// indistinguishable. That collision is real and is preserved here.
/// </summary>
public enum XfsApi : byte
{
    GetInfo = 0,
    Execute = 1
}

/// <summary>
/// A framed transport for XFS-style request/response exchanges.
///
/// <para>
/// Real CEN/XFS has no network protocol: the client loads a vendor service
/// provider DLL (msxfs.dll -&gt; vendor SP) in-process and calls WFSStartUp /
/// WFSOpen / WFSExecute. Remote administration layers such as NCR GBRU,
/// Diebold Vynamic or Wincor Procash add their own TCP transport on top.
/// </para>
///
/// <para>
/// This class models the smallest common denominator of those transports so the
/// lab can be exercised end to end: a 16-byte binary header followed by the
/// payload. The header keeps the shape of the XFS SPI message header so a real
/// protocol adapter can replace this class without touching callers.
/// </para>
///
/// <code>
/// offset size field
/// 0x00   2    hService
/// 0x02   1    bDirection  (0 = request, 1 = reply)
/// 0x03   1    bFlags      (bit0: 0 = WFSGetInfo, 1 = WFSExecute)
/// 0x04   4    ulRequestId
/// 0x08   4    ulCommand
/// 0x0C   4    ulLength    (payload bytes, header excluded)
/// </code>
///
/// Payload = ASCII mnemonic (20 bytes, space padded) || result (4, replies) || XFS body.
/// </summary>
public sealed class XfsTransport : IDisposable
{
    public const int HeaderSize = 16;
    public const int MnemonicSize = 20;
    public const byte FlagExecute = 0x01;

    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private uint _requestId;
    private readonly object _lock = new();

    public string Host { get; }
    public int Port { get; }
    public int TimeoutMs { get; }

    private XfsTransport(TcpClient client, string host, int port, int timeoutMs)
    {
        _client = client;
        _stream = client.GetStream();
        _client.ReceiveTimeout = timeoutMs;
        _client.SendTimeout = timeoutMs;
        Host = host;
        Port = port;
        TimeoutMs = timeoutMs;
    }

    public static XfsTransport Connect(string host, int port, int timeoutMs = 5000)
    {
        var client = new TcpClient { NoDelay = true };
        var ar = client.BeginConnect(host, port, null, null);
        if (!ar.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeoutMs)))
        {
            client.Close();
            throw new IOException($"connect to {host}:{port} timed out after {timeoutMs} ms");
        }
        client.EndConnect(ar);
        return new XfsTransport(client, host, port, timeoutMs);
    }

    /// <summary>Sends one command and reads the matching reply frame.</summary>
    public XfsReply Send(ushort hService, XfsApi api, int command, string mnemonic, ReadOnlySpan<byte> body)
    {
        lock (_lock)
        {
            uint id = ++_requestId;
            int payloadLen = MnemonicSize + body.Length;
            var frame = new byte[HeaderSize + payloadLen];
            BitConverter.GetBytes(hService).CopyTo(frame, 0x00);
            frame[0x02] = 0x00;
            frame[0x03] = api == XfsApi.Execute ? FlagExecute : (byte)0x00;
            BitConverter.GetBytes(id).CopyTo(frame, 0x04);
            BitConverter.GetBytes((uint)command).CopyTo(frame, 0x08);
            BitConverter.GetBytes((uint)payloadLen).CopyTo(frame, 0x0C);
            var mnemonicBytes = Encoding.ASCII.GetBytes(mnemonic);
            Array.Copy(mnemonicBytes, 0, frame, HeaderSize, Math.Min(mnemonicBytes.Length, MnemonicSize));
            body.CopyTo(frame.AsSpan(HeaderSize + MnemonicSize));

            _stream.Write(frame, 0, frame.Length);
            _stream.Flush();

            var header = ReadExactly(HeaderSize);
            ushort respService = BitConverter.ToUInt16(header, 0x00);
            byte dir = header[0x02];
            byte flags = header[0x03];
            uint respId = BitConverter.ToUInt32(header, 0x04);
            int respCommand = (int)BitConverter.ToUInt32(header, 0x08);
            int respLen = (int)BitConverter.ToUInt32(header, 0x0C);

            if (respLen < 0 || respLen > 64 * 1024 * 1024)
                throw new InvalidDataException($"implausible reply length {respLen}");

            var payload = respLen == 0 ? Array.Empty<byte>() : ReadExactly(respLen);
            if (payload.Length < MnemonicSize + 4)
                throw new InvalidDataException($"short reply payload ({payload.Length} bytes)");

            var respMnemonic = Encoding.ASCII.GetString(payload, 0, MnemonicSize).TrimEnd('\0', ' ');
            int result = BitConverter.ToInt32(payload, MnemonicSize);
            var data = payload.AsSpan(MnemonicSize + 4).ToArray();

            return new XfsReply
            {
                HService = respService,
                Direction = dir,
                Api = (flags & FlagExecute) != 0 ? XfsApi.Execute : XfsApi.GetInfo,
                RequestId = respId,
                Command = respCommand,
                Mnemonic = respMnemonic,
                Result = result,
                Data = data
            };
        }
    }

    private byte[] ReadExactly(int count)
    {
        var buf = new byte[count];
        int got = 0;
        while (got < count)
        {
            int n = _stream.Read(buf, got, count - got);
            if (n <= 0) throw new IOException("connection closed by peer mid-frame");
            got += n;
        }
        return buf;
    }

    public void Dispose()
    {
        try { _stream.Dispose(); } catch { /* best effort */ }
        try { _client.Dispose(); } catch { /* best effort */ }
    }
}

public sealed class XfsReply
{
    public ushort HService { get; init; }
    public byte Direction { get; init; }
    public XfsApi Api { get; init; }
    public uint RequestId { get; init; }
    public int Command { get; init; }
    public string Mnemonic { get; init; } = "";
    public int Result { get; init; }
    public byte[] Data { get; init; } = Array.Empty<byte>();

    public bool Ok => Result == XfsConstants.WfsSuccess;
    public string ResultName => XfsConstants.ResultName(Result);

    public string Describe() =>
        $"0x{Command:X4} {Mnemonic} api={Api} result={ResultName} bytes={Data.Length}";
}
