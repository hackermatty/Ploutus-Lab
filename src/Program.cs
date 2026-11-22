using PloutusLab.Deploy;
using PloutusLab.Forensics;
using PloutusLab.Xfs;

namespace PloutusLab;

internal static class Program
{
    private const string Banner = """
    ploutus-lab - authorised ATM/XFS dispense harness
    loopback only | capped amount | two-person approval | append-only audit
    """;

    private static int Main(string[] args)
    {
        var cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "help";
        var audit = Environment.GetEnvironmentVariable("PLOUTUS_AUDIT")
                    ?? Path.Combine(AppContext.BaseDirectory, "audit", $"session-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.log");

        try
        {
            switch (cmd)
            {
                case "exercise":
                    return Exercise(args, audit);
                case "serve":
                    return Serve(args, audit);
                case "analyze":
                    return Analyze(args);
                case "audit":
                    return AuditChecklist(args);
                case "selftest":
                    return SelfTest.Run(Console.Out);
                case "constants":
                    return DumpConstants();
                default:
                    Help();
                    return cmd == "help" || cmd is "-h" or "--help" ? 0 : 64;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.GetType().Name}: {ex.Message}");
            return 70;
        }
    }

    private static int Exercise(string[] args, string audit)
    {
        ulong amount = Arg(args, "--amount") is { } a && ulong.TryParse(a, out var v) ? v : 0;
        bool verbose = args.Contains("--verbose");
        int port = Arg(args, "--port") is { } p && int.TryParse(p, out var pp) ? pp : 0;
        return Scenario.Run(Console.Out, audit, amount, port, verbose);
    }

    private static int Serve(string[] args, string audit)
    {
        int port = Arg(args, "--port") is { } p && int.TryParse(p, out var pp) ? pp : 18500;
        return Scenario.Serve(Console.Out, port, audit);
    }

    private static int Analyze(string[] args)
    {
        var path = Arg(args, "--file") ?? args.Skip(1).FirstOrDefault(a => !a.StartsWith("--"));
        if (path is null || !File.Exists(path))
        {
            Console.Error.WriteLine("usage: ploutus-lab analyze --file <xfs.log> [--ceiling <minor>]");
            return 64;
        }
        ulong ceiling = Arg(args, "--ceiling") is { } c && ulong.TryParse(c, out var cv) ? cv : 40_000;
        return XfsLogAnalyzer.Report(File.ReadLines(path), Console.Out, ceiling);
    }

    private static int AuditChecklist(string[] args)
    {
        var met = new HashSet<string>(
            (Arg(args, "--met") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            StringComparer.OrdinalIgnoreCase);
        return DeploymentAudit.Render(Console.Out, met);
    }

    private static int DumpConstants()
    {
        Console.WriteLine($"CDM offset          {XfsConstants.CdmServiceOffset}");
        Console.WriteLine($"WFS_INF_CDM_STATUS  {XfsConstants.WfsInfCdmStatus} (0x{XfsConstants.WfsInfCdmStatus:X4})");
        Console.WriteLine($"WFS_CMD_CDM_DISPENSE {XfsConstants.WfsCmdCdmDispense} (0x{XfsConstants.WfsCmdCdmDispense:X4})");
        Console.WriteLine($"CIM offset          {XfsConstants.CimServiceOffset}");
        Console.WriteLine($"WFSCDMDISPENSE size {XfsStructures.SizeofDispense}");
        return 0;
    }

    private static string? Arg(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static void Help()
    {
        Console.WriteLine(Banner);
        Console.WriteLine();
        Console.WriteLine("""
        usage:
          ploutus-lab exercise [--amount <minor>] [--port <p>] [--verbose]
              start the loopback lab bus, take two approvals, run a capped
              dispense, reconcile the cassette before/after.

          ploutus-lab serve [--port <p>]
              run only the lab bus so an external client can drive it.
              pre-approved operators come from PLOUTUS_OPERATORS.

          ploutus-lab analyze --file <xfs.log> [--ceiling <minor>]
              score an XFS trace for Ploutus-class behaviours.

          ploutus-lab audit [--met ATM-01,ATM-04,...]
              render the hardening checklist and a score.

          ploutus-lab selftest
              run the guardrail, framing and forensics assertions.

          ploutus-lab constants
              print the CEN/XFS identifiers this build uses.

        environment:
          PLOUTUS_MAX_MINOR     hard dispense ceiling in minor units (default 2000)
          PLOUTUS_WINDOW_START  exercise window start (ISO-8601, UTC)
          PLOUTUS_WINDOW_END    exercise window end   (ISO-8601, UTC)
          PLOUTUS_AUDIT         audit log path
          PLOUTUS_OPERATORS     comma separated operator ids for serve mode
        """);
    }
}
