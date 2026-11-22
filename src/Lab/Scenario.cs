namespace PloutusLab.Xfs;

/// <summary>
/// End-to-end exercise:
///   1. start the loopback lab bus with a standard EUR cassette set
///   2. collect two distinct operator approvals
///   3. open a CDM session through the framed transport
///   4. run one ceiling-clamped dispense and read the cassette back
///   5. reconcile before/after against the audit log
///
/// Everything the scenario does is visible in <see cref="LabBus.Log"/> and in
/// the append-only audit file, so the run can be replayed by a reviewer who
/// was not present.
/// </summary>
public static class Scenario
{
    public static int Run(TextWriter output, string auditPath, ulong amount, int port = 0, bool verbose = false)
    {
        var policy = DispensePolicy.FromEnvironment();
        if (amount == 0) amount = policy.MaxDispenseMinorUnits;

        output.WriteLine("Ploutus-lab exercise");
        output.WriteLine("====================");
        policy.Describe(output);
        output.WriteLine();

        var units = SafeCashUnit.StandardEur();
        var gate = new OperatorGate(auditPath, policy.RequiredApprovals, policy.AcknowledgementTtl);
        var bus = LabBus.Start(port, units.Select(u => new SafeCashUnit
        {
            Number = u.Number, Type = u.Type, Initial = u.Initial, Count = u.Count,
            Maximum = u.Maximum, Currency = u.Currency, Value = u.Value
        }), policy, gate);
        try
        {
            output.WriteLine($"lab bus on 127.0.0.1:{bus.Port}");
            output.WriteLine("cassette before:");
            foreach (var u in bus.Units) output.WriteLine($"  {u.Number:D2} {u.Value / 100.0,8:F2} EUR x {u.Count,4}");

            gate.Grant("analyst-a", policy.AcknowledgementPurpose);
            gate.Grant("analyst-b", policy.AcknowledgementPurpose);
            gate.HasValidAcknowledgement(policy.AcknowledgementPurpose, out var ackState);
            output.WriteLine($"approvals: {ackState}");
            output.WriteLine();

            using var transport = XfsTransport.Connect("127.0.0.1", bus.Port, 4000);
            using var cdm = new CdmClient(transport, hService: 1, gate, policy);

            var status = cdm.Status();
            output.WriteLine($"status    : {status.Describe()}");

            var (reply, stock) = cdm.CashUnitInfo();
            output.WriteLine($"inventory : {reply.ResultName}, {stock.Count} cash units, {stock.Sum(s => (decimal)s.TotalMinorUnits) / 100m:F2} EUR total");

            foreach (var probe in new[] { policy.MaxDispenseMinorUnits + 1, policy.MaxDispenseMinorUnits })
            {
                var check = cdm.CheckDispense(probe);
                output.WriteLine($"policy    : {probe,8} minor -> {(check.Allowed ? "allowed" : "refused")} ({check.Reason})");
            }
            output.WriteLine();

            var requested = Math.Min(amount, policy.MaxDispenseMinorUnits);
            var dispense = cdm.Dispense(requested);
            output.WriteLine($"dispense {requested,8} minor -> {dispense.ResultName}");

            var (afterReply, after) = cdm.CashUnitInfo();
            output.WriteLine();
            output.WriteLine("cassette after:");
            foreach (var u in after)
                output.WriteLine($"  {u.Number:D2} {u.Value / 100.0,8:F2} EUR x {u.Count,4}");

            ulong beforeTotal = stock.Aggregate(0UL, (acc, u) => acc + u.TotalMinorUnits);
            ulong afterTotal = after.Aggregate(0UL, (acc, u) => acc + u.TotalMinorUnits);
            output.WriteLine();
            output.WriteLine($"reconciliation: before={beforeTotal} after={afterTotal} delta={beforeTotal - afterTotal} minor units");

            if (verbose)
            {
                output.WriteLine();
                output.WriteLine("lab bus trace:");
                foreach (var line in bus.Log.Reverse()) output.WriteLine($"  {line}");
            }

            output.WriteLine();
            output.WriteLine($"audit trail: {auditPath}");
            return dispense.Ok ? 0 : 2;
        }
        finally
        {
            bus.Dispose();
        }
    }

    /// <summary>Runs the bus only, so an external client (Burp, a script, a test) can drive it.</summary>
    public static int Serve(TextWriter output, int port, string auditPath)
    {
        var policy = DispensePolicy.FromEnvironment();
        var gate = new OperatorGate(auditPath, policy.RequiredApprovals, policy.AcknowledgementTtl);

        // In serve mode the approvals are pre-seeded from the environment so a
        // remote test client can exercise the flow; every dispense still hits
        // the same ceiling and window checks.
        var operators = (Environment.GetEnvironmentVariable("PLOUTUS_OPERATORS") ?? "analyst-a,analyst-b")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var op in operators) gate.Grant(op, policy.AcknowledgementPurpose);

        var bus = LabBus.Start(port, SafeCashUnit.StandardEur(), policy, gate);
        output.WriteLine($"lab bus listening on 127.0.0.1:{bus.Port} (ctrl-c to stop)");
        policy.Describe(output);
        output.WriteLine($"operators pre-approved: {string.Join(",", operators)}");
        output.Flush();

        var stop = new ManualResetEventSlim();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Set(); };
        stop.Wait();

        output.WriteLine("trace:");
        foreach (var line in bus.Log) output.WriteLine($"  {line}");
        bus.Dispose();
        return 0;
    }
}
