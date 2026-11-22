namespace PloutusLab.Xfs;

/// <summary>
/// The three guardrails that turn a generic CDM client into a lab tool:
/// an amount ceiling, a time window, and a two-person acknowledgement.
/// They are data, not code paths, so an assessor can see exactly what the
/// clone is allowed to do without reading the transport.
/// </summary>
public sealed class DispensePolicy
{
    public ulong MaxDispenseMinorUnits { get; init; } = 2_000;      // 20.00 in a cents currency

    // Default is a rolling +-1h window so an interactive exercise works out of
    // the box; anything derived from the environment replaces it wholesale.
    public TimeWindow Window { get; init; } =
        new(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1));
    public string AcknowledgementPurpose { get; init; } = "dispense";
    public TimeSpan AcknowledgementTtl { get; init; } = TimeSpan.FromSeconds(120);
    public int RequiredApprovals { get; init; } = 2;

    public static DispensePolicy FromEnvironment()
    {
        ulong max = 2_000;
        if (ulong.TryParse(Environment.GetEnvironmentVariable("PLOUTUS_MAX_MINOR"), out var parsed) && parsed > 0)
            max = parsed;

        var start = ParseUtc("PLOUTUS_WINDOW_START") ?? DateTimeOffset.UtcNow.AddHours(-1);
        var end = ParseUtc("PLOUTUS_WINDOW_END") ?? DateTimeOffset.UtcNow.AddHours(1);

        return new DispensePolicy
        {
            MaxDispenseMinorUnits = max,
            Window = new TimeWindow(start, end),
            AcknowledgementPurpose = Environment.GetEnvironmentVariable("PLOUTUS_ACK_PURPOSE") ?? "dispense"
        };
    }

    private static DateTimeOffset? ParseUtc(string name)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(raw)) return null;
        return DateTimeOffset.TryParse(raw, out var value) ? value.ToUniversalTime() : null;
    }

    public void Describe(TextWriter w)
    {
        w.WriteLine($"  ceiling      : {MaxDispenseMinorUnits} minor units");
        w.WriteLine($"  window       : {Window.Start:u} .. {Window.End:u} (utc)");
        w.WriteLine($"  acknowledgement: {RequiredApprovals} approvals for '{AcknowledgementPurpose}', ttl {AcknowledgementTtl.TotalSeconds:0}s");
        w.WriteLine($"  currently    : {(Window.Contains(DateTimeOffset.UtcNow) ? "OPEN" : "CLOSED")}");
    }
}

public readonly record struct TimeWindow(DateTimeOffset Start, DateTimeOffset End)
{
    public bool Contains(DateTimeOffset now) => now >= Start && now <= End;
}
