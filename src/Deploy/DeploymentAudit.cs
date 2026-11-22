namespace PloutusLab.Deploy;

/// <summary>
/// The controls that actually stop Ploutus-class malware on a real estate,
/// expressed as a checklist that a field engineer or an assessor can score.
///
/// This is deliberately *not* a scanner. It does not touch a host. It encodes
/// what the Ploutus family relies on, so an audit can be turned into a finding
/// per unmet control instead of a vague "ATM malware exists" statement.
///
/// Sources for the techniques modelled here: the public analyses of Ploutus-D
/// (2017), Ploutus.B / Ploutus.C, and the ATM malware taxonomy published by
/// Kaspersky, Group-IB and Team Cymru between 2016 and 2020. The common
/// dependencies across all of them are: XFS middleware present and reachable,
/// dispenser command not bound to the transaction state machine, and no
/// integrity check on the process that issues WFSExecute.
/// </summary>
public static class DeploymentAudit
{
    public sealed record Control(
        string Id,
        string Title,
        string WhyItMatters,
        string HowToVerify,
        bool Met = false,
        string? Note = null);

    public static IReadOnlyList<Control> Baseline() => new List<Control>
    {
        new("ATM-01",
            "Application allow-listing on the terminal",
            "Every Ploutus variant needs to get its binary onto the ATM and get it to run. WDAC/AppLocker with a signed-publisher rule blocks the dropped executable even when an operator is tricked into copying it.",
            "Confirm the WDAC/AppLocker policy is in enforce mode, not audit; attempt to launch an unsigned copy of calc.exe from C:\\Temp."),

        new("ATM-02",
            "XFS dispense requires an open transaction context",
            "The malware's core primitive is a bare WFSExecute(WFS_CMD_CDM_DISPENSE). If the application layer only accepts dispense inside a state machine that was opened by a card + PIN + amount, a rogue process cannot mint one.",
            "Review the ATM application's XFS wrapper: does it expose dispense as a public method callable from anywhere, or only from the transaction controller?"),

        new("ATM-03",
            "Least privilege for the kiosk account",
            "Most families run in the interactive user context of the ATM application. That user typically has write access to the application directory, which is how persistence survives reboots.",
            "Check ACLs on the application directory and on HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; confirm the kiosk user cannot write to either."),

        new("ATM-04",
            "Service provider DLL integrity monitoring",
            "Ploutus-D shipped a malicious msxfs.dll next to the application. Hash-pinning the XFS service provider chain (msxfs.dll plus vendor SPs) detects the swap.",
            "Compare SHA-256 of every DLL in the XFS chain against the vendor's signed manifest; alert on drift."),

        new("ATM-05",
            "Dispenser interlock tied to physical cassette state",
            "A dispense that empties a cassette in seconds is physically distinguishable. Cassette-level counters reconciled against the host's transaction log catch the theft after the fact and deter the insider case.",
            "Confirm cassette counters are uploaded to the switch/host at least daily and that a mismatch raises an incident."),

        new("ATM-06",
            "No unattended remote-control paths",
            "Ploutus.C and later were delivered through remote management agents and, in some campaigns, through the vendor's own remote-access tooling. An agent that can push and execute binaries is the delivery vector.",
            "Inventory every remote-management agent; require MFA, session recording and a change ticket for binary deployment."),

        new("ATM-07",
            "Egress filtering on the terminal network",
            "Command-and-control for these families is small: a few HTTP or DNS beacons. A terminal that can only reach its host and its update server has nowhere to phone home.",
            "Verify the terminal VLAN ACL allows only the host endpoints and the patch/AV infrastructure; test with a curl to an external IP."),

        new("ATM-08",
            "Tamper-evident boot and disk encryption",
            "Offline tampering (boot from USB, mount the disk, edit the XFS config) is a documented path for several families. Secure Boot plus BitLocker with TPM pinning closes it.",
            "Check Secure Boot state and that BitLocker/TPM is enabled with a PIN or network unlock, not a plain key file."),

        new("ATM-09",
            "Log shipping off the terminal",
            "Everything in XFS is locally logged and locally deletable. Shipping the XFS journal to a SIEM in near real time is what makes the dispense-without-card pattern detectable at all.",
            "Confirm the XFS journal leaves the terminal within 60 seconds and that the SIEM has a rule for WFS_CMD_CDM_DISPENSE without a preceding PIN_ENTRY."),

        new("ATM-10",
            "Physical port and keyboard controls",
            "The 2017 Ploutus-D campaign used the numeric keypad with a special sequence to trigger the dispense UI. USB port blocking plus a keypad that cannot inject function keys removes the operator-assisted path.",
            "Inspect USB ports for blocks/glue; verify the keypad firmware cannot emit F-keys or the vendor's service sequence without a physical service key."),
    };

    public static int Render(TextWriter w, ISet<string> metIds)
    {
        var controls = Baseline();
        int met = 0;
        w.WriteLine("ATM hardening audit - Ploutus-class malware baseline");
        w.WriteLine(new string('=', 58));
        foreach (var c in controls)
        {
            bool isMet = metIds.Contains(c.Id);
            if (isMet) met++;
            w.WriteLine();
            w.WriteLine($"{(isMet ? "[x]" : "[ ]")} {c.Id}  {c.Title}");
            w.WriteLine($"      why : {c.WhyItMatters}");
            w.WriteLine($"      test: {c.HowToVerify}");
        }
        w.WriteLine();
        w.WriteLine($"score: {met}/{controls.Count} controls met");
        return met == controls.Count ? 0 : 1;
    }
}
