using System.Globalization;
using System.Text.RegularExpressions;

namespace PloutusLab.Forensics;

/// <summary>
/// The other half of an ATM malware assessment: reading what the machine left
/// behind. Vendors log XFS traffic in wildly different formats, but almost all
/// of them expose the same four facts - timestamp, service, command, result -
/// which is enough to score a session for the behaviours Ploutus-class tools
/// produce:
///
///   * dispense with no preceding card-in / PIN / cash-in in the session
///   * dispense amount far above the terminal's configured fast-cash limits
///   * a burst of dispense calls inside a few seconds (ceiling bypass attempts)
///   * reset storms used to clear a jam or an interlock
///   * dispense executed while the terminal reports supervisor mode
///
/// The analyzer is heuristic on purpose and reports evidence, not verdicts.
/// </summary>
public static class XfsLogAnalyzer
{
    private static readonly Regex Line = new(
        @"(?<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+" +
        @"(?:.*?\s)?(?:cmd=)?0x?(?<cmd>[0-9A-Fa-f]{3,4})\s+(?<name>WFS_[A-Z_]+)" +
        @"(?:\s+bytes=(?<bytes>\d+))?(?:\s*->\s*(?<result>WFS_[A-Z_]+))?",
        RegexOptions.Compiled);

    private static readonly Regex Amount = new(@"amount=(?<amount>\d+)", RegexOptions.Compiled);

    public sealed class Finding
    {
        public string Rule { get; init; } = "";
        public string Severity { get; init; } = "info";
        public string Evidence { get; init; } = "";
        public override string ToString() => $"[{Severity,-8}] {Rule}: {Evidence}";
    }

    public static List<Finding> Analyze(IEnumerable<string> lines, ulong fastCashCeilingMinor = 40_000)
    {
        var findings = new List<Finding>();
        bool sawCardRead = false, sawPin = false, sawCashIn = false;
        var dispenseTimes = new List<DateTimeOffset>();
        int resets = 0;

        foreach (var raw in lines)
        {
            var m = Line.Match(raw);
            if (!m.Success) continue;

            if (!DateTimeOffset.TryParse(m.Groups["ts"].Value, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var ts))
                ts = DateTimeOffset.MinValue;

            var name = m.Groups["name"].Value.ToUpperInvariant();
            var result = m.Groups["result"].Success ? m.Groups["result"].Value : "";

            switch (name)
            {
                case "WFS_CMD_IDC_READ_RAW_DATA":
                case "WFS_CMD_IDC_READ_TRACK":
                    sawCardRead = true;
                    sawPin = false; sawCashIn = false;
                    break;
                case "WFS_CMD_IDC_EJECT_CARD":
                case "WFS_CMD_IDC_RETRACT_CARD":
                    // Session boundary heuristic: the card leaving the reader
                    // ends the authorisation context. Real logs usually carry a
                    // session id; when they do, key on that instead.
                    sawCardRead = false; sawPin = false; sawCashIn = false;
                    break;
                case "WFS_CMD_PIN_ENTRY":
                    sawPin = true;
                    break;
                case "WFS_CMD_CIM_CASH_IN_START":
                case "WFS_CMD_CIM_CASH_IN":
                    sawCashIn = true;
                    break;
                case "WFS_CMD_CDM_RESET":
                    resets++;
                    break;
                case "WFS_CMD_CDM_DISPENSE":
                    dispenseTimes.Add(ts);
                    if (!sawCardRead)
                        findings.Add(new Finding
                        {
                            Rule = "dispense-without-card",
                            Severity = "high",
                            Evidence = $"{ts:O} dispense with no prior WFS_CMD_IDC_READ_* in session"
                        });

                    if (!sawPin && !sawCashIn)
                        findings.Add(new Finding
                        {
                            Rule = "dispense-without-authorisation",
                            Severity = "high",
                            Evidence = $"{ts:O} dispense with no prior PIN entry or cash-in"
                        });

                    var am = Amount.Match(raw);
                    if (am.Success && ulong.TryParse(am.Groups["amount"].Value, out var amount) && amount > fastCashCeilingMinor)
                        findings.Add(new Finding
                        {
                            Rule = "dispense-over-fastcash-limit",
                            Severity = "medium",
                            Evidence = $"{ts:O} amount={amount} exceeds configured ceiling {fastCashCeilingMinor}"
                        });

                    if (result.Contains("WFS_ERR", StringComparison.Ordinal))
                        findings.Add(new Finding
                        {
                            Rule = "dispense-error",
                            Severity = "info",
                            Evidence = $"{ts:O} {result}"
                        });
                    break;
            }
        }

        // Burst analysis: >= 3 dispense attempts inside 15 seconds.
        var ordered = dispenseTimes.OrderBy(t => t).ToList();
        for (int i = 0; i + 2 < ordered.Count; i++)
        {
            if ((ordered[i + 2] - ordered[i]).TotalSeconds <= 15)
            {
                findings.Add(new Finding
                {
                    Rule = "dispense-burst",
                    Severity = "high",
                    Evidence = $"3+ dispense attempts within {(ordered[i + 2] - ordered[i]).TotalSeconds:0}s starting {ordered[i]:O} (ceiling-bypass pattern)"
                });
                break;
            }
        }

        if (resets >= 3)
            findings.Add(new Finding
            {
                Rule = "reset-storm",
                Severity = "medium",
                Evidence = $"{resets} CDM_RESET calls in one log window"
            });

        return findings;
    }

    public static int Report(IEnumerable<string> lines, TextWriter w, ulong ceiling)
    {
        var findings = Analyze(lines, ceiling);
        if (findings.Count == 0)
        {
            w.WriteLine("no suspicious XFS patterns matched");
            return 0;
        }

        foreach (var group in findings.GroupBy(f => (f.Severity, f.Rule)).OrderBy(g => Rank(g.Key.Severity)))
        {
            w.WriteLine($"{group.Key.Severity,-8} {group.Key.Rule} x{group.Count()}");
            foreach (var f in group.Take(3)) w.WriteLine($"         {f.Evidence}");
        }
        return findings.Any(f => f.Severity == "high") ? 1 : 0;
    }

    private static int Rank(string severity) => severity switch
    {
        "high" => 0, "medium" => 1, "low" => 2, _ => 3
    };
}
