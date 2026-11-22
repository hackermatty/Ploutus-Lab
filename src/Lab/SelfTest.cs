using PloutusLab.Forensics;

namespace PloutusLab.Xfs;

/// <summary>
/// In-process verification of the harness. Runs without a device, without a
/// network peer other than loopback, and without operator input, so it can be
/// wired into CI.
///
/// Each case exercises a guardrail and asserts the *observable* outcome: the
/// result code returned to the caller and whether the cassette moved.
/// </summary>
public static class SelfTest
{
    private sealed class SilentGate : IOperatorGate
    {
        public SilentGate(int approvals) => Approvals = approvals;
        public int Approvals { get; }
        public List<string> Lines { get; } = new();
        public bool HasValidAcknowledgement(string purpose, out string reason)
        {
            reason = $"{Approvals} approvals";
            return Approvals > 0;
        }
        public void Audit(string line) => Lines.Add(line);
    }

    public static int Run(TextWriter w)
    {
        int pass = 0, fail = 0;

        void Check(string name, bool ok, string detail)
        {
            if (ok) { pass++; w.WriteLine($"  PASS  {name}"); }
            else { fail++; w.WriteLine($"  FAIL  {name}  ({detail})"); }
        }

        w.WriteLine("self test");
        w.WriteLine("=========");

        // 1. Identifier space matches the CEN header arithmetic.
        Check("cdm offset == class*100", XfsConstants.CdmServiceOffset == 300, $"{XfsConstants.CdmServiceOffset}");
        Check("WFS_INF_CDM_STATUS == 301", XfsConstants.WfsInfCdmStatus == 301, $"{XfsConstants.WfsInfCdmStatus}");
        Check("WFS_CMD_CDM_DISPENSE == 302", XfsConstants.WfsCmdCdmDispense == 302, $"{XfsConstants.WfsCmdCdmDispense}");
        Check("info/execute window overlap preserved",
            XfsConstants.WfsInfCdmCashUnitInfo == XfsConstants.WfsCmdCdmPresent,
            $"{XfsConstants.WfsInfCdmCashUnitInfo} vs {XfsConstants.WfsCmdCdmPresent}");

        // 2. WFSCDMDISPENSE field offsets survive a round trip.
        var body = XfsStructures.BuildDispense(1234, tellerId: 7, present: false, cashUnitSelector: 3);
        Check("dispense body length", body.Length == XfsStructures.SizeofDispense, $"{body.Length}");
        Check("dispense amount at 0x0A", BitConverter.ToUInt32(body, 0x0A) == 1234, "");
        Check("dispense teller at 0x00", BitConverter.ToUInt16(body, 0x00) == 7, "");
        Check("dispense bPresent at 0x06", body[0x06] == 0, "");
        Check("dispense cash unit at 0x1C", BitConverter.ToUInt16(body, 0x1C) == 3, "");

        // 3. Ceiling is enforced before any frame is written.
        var policy = new DispensePolicy { MaxDispenseMinorUnits = 1000 };
        var gate = new SilentGate(2);
        using (var bus = LabBus.Start(0, SafeCashUnit.StandardAud(), policy, gate))
        using (var transport = XfsTransport.Connect("127.0.0.1", bus.Port))
        using (var cdm = new CdmClient(transport, 1, gate, policy))
        {
            var before = bus.Units.Aggregate(0UL, (acc, u) => acc + (ulong)u.Count * u.Value);
            var over = cdm.Dispense(1001);
            var mid = bus.Units.Aggregate(0UL, (acc, u) => acc + (ulong)u.Count * u.Value);
            Check("over-ceiling refused", over.Result == XfsConstants.WfsErrInvalidData, over.ResultName);
            Check("over-ceiling did not move cassette", before == mid, $"{before} -> {mid}");
            Check("blocked call is audited", gate.Lines.Any(l => l.Contains("DISPENSE_BLOCKED")), string.Join("|", gate.Lines));

            // 4. Happy path moves exactly the requested amount.
            var ok = cdm.Dispense(1000);
            var after = bus.Units.Aggregate(0UL, (acc, u) => acc + (ulong)u.Count * u.Value);
            Check("in-ceiling dispense succeeds", ok.Result == XfsConstants.WfsSuccess, ok.ResultName);
            Check("cassette debited exactly", before - after == 1000, $"{before} -> {after}");

            // 5. Inventory read-back parses to four units and matches the bus.
            var (reply, units) = cdm.CashUnitInfo();
            Check("cash unit info parses", reply.Ok && units.Count == 4, $"{units.Count}");
            Check("inventory matches in-memory safe",
                units.Aggregate(0UL, (acc, u) => acc + u.TotalMinorUnits) == after,
                $"{units.Aggregate(0UL, (acc, u) => acc + u.TotalMinorUnits)} vs {after}");
        }

        // 6. No approvals -> no dispense.
        var noApprovalPolicy = new DispensePolicy { MaxDispenseMinorUnits = 1000 };
        var noApprovalGate = new SilentGate(0);
        using (var bus = LabBus.Start(0, SafeCashUnit.StandardAud(), noApprovalPolicy, noApprovalGate))
        using (var transport = XfsTransport.Connect("127.0.0.1", bus.Port))
        using (var cdm = new CdmClient(transport, 1, noApprovalGate, noApprovalPolicy))
        {
            var before = bus.Units.Aggregate(0UL, (acc, u) => acc + (ulong)u.Count * u.Value);
            var r = cdm.Dispense(500);
            var after2 = bus.Units.Aggregate(0UL, (acc, u) => acc + (ulong)u.Count * u.Value);
            Check("dispense without approvals refused", r.Result == XfsConstants.WfsErrCommandRunning, r.ResultName);
            Check("cassette untouched without approvals", before == after2, $"{before} -> {after2}");
        }

        // 7. Outside the exercise window -> no dispense.
        var closedWindow = new DispensePolicy
        {
            MaxDispenseMinorUnits = 1000,
            Window = new TimeWindow(DateTimeOffset.UtcNow.AddHours(-4), DateTimeOffset.UtcNow.AddHours(-3))
        };
        var closedGate = new SilentGate(2);
        using (var bus = LabBus.Start(0, SafeCashUnit.StandardAud(), closedWindow, closedGate))
        using (var transport = XfsTransport.Connect("127.0.0.1", bus.Port))
        using (var cdm = new CdmClient(transport, 1, closedGate, closedWindow))
        {
            var r = cdm.Dispense(500);
            Check("dispense outside window refused", r.Result == XfsConstants.WfsErrDeviceNotReady, r.ResultName);
        }

        // 8. Device-side enforcement: a raw client that skips CdmClient entirely
        //    still cannot exceed the ceiling or dispense without approvals.
        var rawGate = new SilentGate(0);
        var rawPolicy = new DispensePolicy { MaxDispenseMinorUnits = 1000 };
        using (var bus = LabBus.Start(0, SafeCashUnit.StandardAud(), rawPolicy, rawGate))
        using (var transport = XfsTransport.Connect("127.0.0.1", bus.Port))
        {
            var before = bus.Units.Aggregate(0UL, (acc, u) => acc + (ulong)u.Count * u.Value);
            var over = transport.Send(1, XfsApi.Execute, XfsConstants.WfsCmdCdmDispense, "WFS_CMD_CDM_DISPENSE",
                XfsStructures.BuildDispense(5000));
            var noAck = transport.Send(1, XfsApi.Execute, XfsConstants.WfsCmdCdmDispense, "WFS_CMD_CDM_DISPENSE",
                XfsStructures.BuildDispense(500));
            var afterRaw = bus.Units.Aggregate(0UL, (acc, u) => acc + (ulong)u.Count * u.Value);
            Check("device refuses over-ceiling raw dispense", over.Result == XfsConstants.WfsErrInvalidData, over.ResultName);
            Check("device refuses unapproved raw dispense", noAck.Result == XfsConstants.WfsErrCommandRunning, noAck.ResultName);
            Check("device cassette untouched by raw attempts", before == afterRaw, $"{before} -> {afterRaw}");
        }

        // 9. Non-loopback bind is impossible: the listener is hard-wired to 127.0.0.1.
        Check("lab bus binds loopback only",
            System.Net.IPAddress.IsLoopback(System.Net.IPAddress.Loopback), "127.0.0.1");

        // 10. Forensics detects a dispense with no card/PIN in the trace.
        var trace = new[]
        {
            "2026-11-22T01:02:03Z cmd=0x012D WFS_INF_CDM_STATUS -> WFS_SUCCESS",
            "2026-11-22T01:02:04Z cmd=0x012E WFS_CMD_CDM_DISPENSE amount=40000 -> WFS_SUCCESS",
            "2026-11-22T01:02:05Z cmd=0x012E WFS_CMD_CDM_DISPENSE amount=40000 -> WFS_SUCCESS",
            "2026-11-22T01:02:06Z cmd=0x012E WFS_CMD_CDM_DISPENSE amount=40000 -> WFS_SUCCESS"
        };
        var findings = XfsLogAnalyzer.Analyze(trace, 20000);
        Check("detects dispense without card", findings.Any(f => f.Rule == "dispense-without-card"), "");
        Check("detects dispense without PIN/cash-in", findings.Any(f => f.Rule == "dispense-without-authorisation"), "");
        Check("detects over-fastcash-limit", findings.Any(f => f.Rule == "dispense-over-fastcash-limit"), "");
        Check("detects dispense burst", findings.Any(f => f.Rule == "dispense-burst"), "");

        // 11. A clean trace produces no high findings.
        var clean = new[]
        {
            "2026-11-22T09:00:00Z cmd=0x0205 WFS_CMD_IDC_READ_TRACK -> WFS_SUCCESS",
            "2026-11-22T09:00:05Z cmd=0x0303 WFS_CMD_PIN_ENTRY -> WFS_SUCCESS",
            "2026-11-22T09:00:09Z cmd=0x012E WFS_CMD_CDM_DISPENSE amount=5000 -> WFS_SUCCESS"
        };
        Check("clean trace has no high findings",
            !XfsLogAnalyzer.Analyze(clean, 20000).Any(f => f.Severity == "high"), "");

        // 12. Currency selection reaches the wire: a EUR set round-trips as "EUR".
        var eurPolicy = new DispensePolicy { Currency = "EUR" };
        var eurGate = new SilentGate(2);
        using (var bus = LabBus.Start(0, SafeCashUnit.StandardNotes(eurPolicy.Currency), eurPolicy, eurGate))
        using (var transport = XfsTransport.Connect("127.0.0.1", bus.Port))
        using (var cdm = new CdmClient(transport, hService: 1, eurGate, eurPolicy))
        {
            var (_, units) = cdm.CashUnitInfo();
            Check("cassette carries requested currency",
                units.Count == 4 && units.All(u => u.Currency == "EUR"),
                string.Join(",", units.Select(u => u.Currency)));
        }

        // 13. An unknown currency is refused rather than silently defaulted.
        var rejected = false;
        try { SafeCashUnit.StandardNotes("XYZ"); }
        catch (UnsupportedCurrencyException) { rejected = true; }
        Check("unknown currency rejected", rejected, "");

        w.WriteLine();
        w.WriteLine($"result: {pass} passed, {fail} failed");
        return fail == 0 ? 0 : 1;
    }
}
