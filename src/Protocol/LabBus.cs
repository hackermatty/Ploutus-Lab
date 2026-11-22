using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace PloutusLab.Xfs;

/// <summary>
/// The instrumented "ATM" side of the lab: a loopback-only XFS endpoint that
/// speaks the framing in <see cref="XfsTransport"/> against an in-memory safe.
///
/// Scope enforcement is deliberately duplicated here (bind address whitelist)
/// because a harness that can be pointed at a real host is not a harness.
/// Only 127.0.0.1 / ::1 are accepted; there is no configuration to widen it.
/// </summary>
public sealed class LabBus : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<SafeCashUnit> _units;
    private readonly DispensePolicy _policy;
    private readonly IOperatorGate _gate;
    private readonly ConcurrentBag<string> _log = new();
    private Task? _acceptLoop;

    public const int MaxItemsPerDispense = 40;   // matches typical CDM cassette config
    public int Port { get; private set; }

    public IReadOnlyList<SafeCashUnit> Units => _units;
    public IReadOnlyList<string> Log => _log.ToArray();

    public LabBus(int port, IEnumerable<SafeCashUnit> units, DispensePolicy policy, IOperatorGate gate)
    {
        Port = port;
        _units = units.ToList();
        _policy = policy;
        _gate = gate;
        _listener = new TcpListener(IPAddress.Loopback, port);
    }

    /// <summary>
    /// Starts the lab device. The policy and the operator gate are mandatory:
    /// a raw client speaking the framing directly to this endpoint must hit the
    /// same ceiling, window and approval checks as <see cref="CdmClient"/>.
    /// Device-side enforcement is what makes "serve" mode as capped as the
    /// in-process exercise.
    /// </summary>
    public static LabBus Start(int port, IEnumerable<SafeCashUnit> units, DispensePolicy policy, IOperatorGate gate)
    {
        var bus = new LabBus(port, units, policy, gate);
        bus._listener.Start();
        bus.Port = ((IPEndPoint)bus._listener.LocalEndpoint).Port;
        bus._acceptLoop = Task.Run(() => bus.AcceptLoopAsync(bus._cts.Token));
        bus.Trace($"LABBUS listening on 127.0.0.1:{bus.Port} units={string.Join(",", bus._units.Select(u => u.Number))}");
        return bus;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }

            var remote = client.Client.RemoteEndPoint as IPEndPoint;
            if (remote is null || !IPAddress.IsLoopback(remote.Address))
            {
                Trace($"REJECT non-loopback peer {remote}");
                client.Dispose();
                continue;
            }

            _ = Task.Run(() => ServeAsync(client, ct), ct);
        }
    }

    private async Task ServeAsync(TcpClient client, CancellationToken ct)
    {
        using var _ = client;
        var stream = client.GetStream();
        var header = new byte[XfsTransport.HeaderSize];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                if (!await ReadExactlyAsync(stream, header, ct)) return;
                ushort hService = BitConverter.ToUInt16(header, 0x00);
                uint requestId = BitConverter.ToUInt32(header, 0x04);
                int command = (int)BitConverter.ToUInt32(header, 0x08);
                int length = (int)BitConverter.ToUInt32(header, 0x0C);
                if (length < 0 || length > 1 << 20) { Trace($"BADLEN {length}"); return; }

                var payload = new byte[length];
                if (!await ReadExactlyAsync(stream, payload, ct)) return;

                var mnemonic = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(XfsTransport.MnemonicSize, payload.Length)).TrimEnd('\0', ' ');
                var body = payload.Length > XfsTransport.MnemonicSize ? payload[XfsTransport.MnemonicSize..] : Array.Empty<byte>();

                byte flags = header[0x03];
                bool isExecute = (flags & XfsTransport.FlagExecute) != 0;
                var (result, data) = Execute(isExecute, command, body);
                Trace($"RX api={(isExecute ? "execute" : "getinfo")} cmd=0x{command:X4} {mnemonic} bytes={body.Length} -> {XfsConstants.ResultName(result)} ret={data.Length}");

                int outLen = XfsTransport.MnemonicSize + 4 + data.Length;
                var frame = new byte[XfsTransport.HeaderSize + outLen];
                BitConverter.GetBytes(hService).CopyTo(frame, 0x00);
                frame[0x02] = 0x01;
                frame[0x03] = flags;
                BitConverter.GetBytes(requestId).CopyTo(frame, 0x04);
                BitConverter.GetBytes((uint)command).CopyTo(frame, 0x08);
                BitConverter.GetBytes((uint)outLen).CopyTo(frame, 0x0C);
                var mBytes = System.Text.Encoding.ASCII.GetBytes(mnemonic);
                Array.Copy(mBytes, 0, frame, XfsTransport.HeaderSize, Math.Min(mBytes.Length, XfsTransport.MnemonicSize));
                BitConverter.GetBytes(result).CopyTo(frame, XfsTransport.HeaderSize + XfsTransport.MnemonicSize);
                data.CopyTo(frame, XfsTransport.HeaderSize + XfsTransport.MnemonicSize + 4);
                await stream.WriteAsync(frame, ct);
            }
        }
        catch (IOException) { /* client went away */ }
        catch (OperationCanceledException) { /* shutdown */ }
    }

    /// <summary>
    /// Dispatches on (API, command). The API selector is required because the
    /// numeric windows overlap: 303 is both WFS_INF_CDM_CASH_UNIT_INFO and
    /// WFS_CMD_CDM_PRESENT, exactly as in the CEN headers.
    /// </summary>
    private (int result, byte[] data) Execute(bool isExecute, int command, ReadOnlySpan<byte> body)
    {
        if (!isExecute)
        {
            return command switch
            {
                XfsConstants.WfsInfCdmStatus       => (XfsConstants.WfsSuccess, BuildStatus()),
                XfsConstants.WfsInfCdmCashUnitInfo => (XfsConstants.WfsSuccess, BuildCashUnitInfo()),
                XfsConstants.WfsInfCimCashUnitInfo => (XfsConstants.WfsSuccess, BuildCashUnitInfo()),
                _ => (XfsConstants.WfsErrInvalidCommand, Array.Empty<byte>())
            };
        }

        switch (command)
        {
            case XfsConstants.WfsCmdCdmDispense:
                return Dispense(body);

            case XfsConstants.WfsCmdCdmPresent:
                return (XfsConstants.WfsSuccess, Array.Empty<byte>());

            case XfsConstants.WfsCmdCdmRetract:
                RetractAll();
                return (XfsConstants.WfsSuccess, Array.Empty<byte>());

            case XfsConstants.WfsCmdCdmReset:
                foreach (var u in _units) u.Status = 0;
                return (XfsConstants.WfsSuccess, Array.Empty<byte>());

            default:
                return (XfsConstants.WfsErrUnsupportedCommand, Array.Empty<byte>());
        }
    }

    private (int result, byte[] data) Dispense(ReadOnlySpan<byte> body)
    {
        if (body.Length < XfsStructures.SizeofDispense)
            return (XfsConstants.WfsErrInvalidData, Array.Empty<byte>());

        bool present = body[0x06] != 0;
        uint amount = BitConverter.ToUInt32(body[0x0A..]);
        ushort selector = BitConverter.ToUInt16(body[0x1C..]);

        // Device-side guardrails. These duplicate CdmClient's checks on purpose:
        // the dispenser itself must not be willing to hand out cash just because
        // a caller skipped the client library.
        if (amount == 0 || amount > _policy.MaxDispenseMinorUnits)
        {
            Trace($"DISPENSE_REFUSED amount={amount} policy_ceiling={_policy.MaxDispenseMinorUnits}");
            return (XfsConstants.WfsErrInvalidData, Array.Empty<byte>());
        }

        if (!_policy.Window.Contains(DateTimeOffset.UtcNow))
        {
            Trace("DISPENSE_REFUSED outside_service_window");
            return (XfsConstants.WfsErrDeviceNotReady, Array.Empty<byte>());
        }

        if (!_gate.HasValidAcknowledgement(_policy.AcknowledgementPurpose, out var why))
        {
            Trace($"DISPENSE_REFUSED no_acknowledgement ({why})");
            return (XfsConstants.WfsErrCommandRunning, Array.Empty<byte>());
        }

        var candidates = selector == 0 ? _units : _units.Where(u => u.Number == selector).ToList();
        if (candidates.Count == 0)
        {
            Trace($"DISPENSE_REFUSED unknown_cash_unit={selector}");
            return (XfsConstants.WfsErrInvalidCashUnit, Array.Empty<byte>());
        }

        // Greedy, largest denomination first - the same class of algorithm a
        // real cash handler uses, and the reason a mixed cassette can drain
        // faster than the operator expects.
        var plan = new List<(SafeCashUnit Unit, int Notes)>();
        ulong remaining = amount;
        foreach (var unit in candidates.OrderByDescending(u => u.Value))
        {
            if (unit.Value == 0) continue;
            uint notes = (uint)Math.Min(remaining / unit.Value, unit.Count);
            if (notes == 0) continue;
            plan.Add((unit, (int)notes));
            remaining -= notes * (ulong)unit.Value;
        }

        if (remaining != 0)
        {
            Trace($"DISPENSE_REFUSED amount={amount} unallocatable_remainder={remaining}");
            return (XfsConstants.WfsErrTooManyItems, Array.Empty<byte>());
        }

        int totalNotes = plan.Sum(p => p.Notes);
        if (totalNotes > MaxItemsPerDispense)
        {
            Trace($"DISPENSE_REFUSED notes={totalNotes} limit={MaxItemsPerDispense}");
            return (XfsConstants.WfsErrTooManyItems, Array.Empty<byte>());
        }

        foreach (var (unit, notes) in plan)
            unit.Count -= (uint)notes;

        Trace($"DISPENSE_OK amount={amount} notes={totalNotes} present={present} plan=[{string.Join(" ", plan.Select(p => $"{p.Unit.Number}x{p.Notes}"))}]");
        return (XfsConstants.WfsSuccess, Array.Empty<byte>());
    }

    private void RetractAll()
    {
        foreach (var u in _units)
        {
            if (u.Presented > 0)
            {
                u.Count += (uint)u.Presented;
                u.Presented = 0;
            }
        }
    }

    private byte[] BuildStatus() => new byte[8];

    private byte[] BuildCashUnitInfo()
    {
        int n = _units.Count;
        var buf = new byte[2 + n * XfsStructures.SizeofCashUnitCore];
        BitConverter.GetBytes((ushort)n).CopyTo(buf, 0);
        int o = 2;
        foreach (var u in _units)
        {
            BitConverter.GetBytes(u.Number).CopyTo(buf, o + 0x00);
            BitConverter.GetBytes(u.Type).CopyTo(buf, o + 0x02);
            BitConverter.GetBytes(u.Status).CopyTo(buf, o + 0x04);
            BitConverter.GetBytes(u.Initial).CopyTo(buf, o + 0x08);
            BitConverter.GetBytes(u.Count).CopyTo(buf, o + 0x0C);
            BitConverter.GetBytes(u.Rejected).CopyTo(buf, o + 0x10);
            BitConverter.GetBytes(u.Maximum).CopyTo(buf, o + 0x14);
            BitConverter.GetBytes(u.Currency).CopyTo(buf, o + 0x1C);
            BitConverter.GetBytes(u.Value).CopyTo(buf, o + 0x20);
            o += XfsStructures.SizeofCashUnitCore;
        }
        return buf;
    }

    private static async Task<bool> ReadExactlyAsync(NetworkStream s, byte[] buf, CancellationToken ct)
    {
        int got = 0;
        while (got < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(got), ct);
            if (n <= 0) return false;
            got += n;
        }
        return true;
    }

    private void Trace(string line) => _log.Add($"{DateTimeOffset.UtcNow:HH:mm:ss.fff} {line}");

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { }
        try { _acceptLoop?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cts.Dispose();
    }
}

public sealed class SafeCashUnit
{
    public ushort Number { get; init; }
    public ushort Type { get; init; } = 1;
    public ushort Status { get; set; }
    public uint Initial { get; init; }
    public uint Count { get; set; }
    public uint Rejected { get; set; }
    public uint Maximum { get; init; } = 2000;
    public char Currency { get; init; } = 'E';
    public uint Value { get; init; }          // in minor units, e.g. 5000 = 50.00
    public int Presented { get; set; }

    public static SafeCashUnit[] StandardEur() => new[]
    {
        new SafeCashUnit { Number = 1, Value = 5000, Initial = 400, Count = 400 },
        new SafeCashUnit { Number = 2, Value = 2000, Initial = 600, Count = 600 },
        new SafeCashUnit { Number = 3, Value = 1000, Initial = 500, Count = 500 },
        new SafeCashUnit { Number = 4, Value = 500,  Initial = 800, Count = 800 },
    };
}
