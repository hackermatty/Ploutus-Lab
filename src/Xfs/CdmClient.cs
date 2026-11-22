namespace PloutusLab.Xfs;

/// <summary>
/// Thin typed wrapper over a CDM service: status, cash inventory, dispense.
///
/// Every method maps 1:1 onto a CEN/XFS command documented in CWA 16926-5, and
/// each call states whether it goes through WFSGetInfo or WFSExecute because
/// the command numbers overlap between the two entry points.
///
/// The class deliberately exposes dispense as a primitive; the policy that
/// decides whether a dispense may happen lives in <see cref="DispensePolicy"/>
/// and is enforced here, in the one place that writes the frame, so a caller
/// cannot route around it.
/// </summary>
public sealed class CdmClient : IDisposable
{
    private readonly XfsTransport _transport;
    private readonly IOperatorGate _gate;
    private readonly DispensePolicy _policy;

    public ushort HService { get; }

    public CdmClient(XfsTransport transport, ushort hService, IOperatorGate gate, DispensePolicy policy)
    {
        _transport = transport;
        HService = hService;
        _gate = gate;
        _policy = policy;
    }

    /// <summary>WFSGetInfo(WFS_INF_CDM_STATUS = 301).</summary>
    public XfsReply Status()
    {
        var reply = _transport.Send(HService, XfsApi.GetInfo, XfsConstants.WfsInfCdmStatus, "WFS_INF_CDM_STATUS", default);
        _gate.Audit($"CDM_INFO_STATUS -> {reply.ResultName}");
        return reply;
    }

    /// <summary>WFSGetInfo(WFS_INF_CDM_CASH_UNIT_INFO = 303).</summary>
    public (XfsReply Reply, List<XfsStructures.CashUnit> Units) CashUnitInfo()
    {
        var reply = _transport.Send(HService, XfsApi.GetInfo, XfsConstants.WfsInfCdmCashUnitInfo, "WFS_INF_CDM_CASHUNITINFO", default);
        var units = reply.Ok ? XfsStructures.ParseCashUnitInfo(reply.Data) : new List<XfsStructures.CashUnit>();
        _gate.Audit($"CDM_INFO_CASHUNIT -> {reply.ResultName} units={units.Count}");
        return (reply, units);
    }

    /// <summary>
    /// WFSExecute(WFS_CMD_CDM_DISPENSE = 302).
    ///
    /// The amount is in minimum dispense units (cents). Before the frame is
    /// written this checks, in order: the configured ceiling, the exercise
    /// window, and the two-person acknowledgement.
    /// </summary>
    public XfsReply Dispense(ulong amountMinorUnits, bool present = true, ushort cashUnitSelector = 0)
    {
        var check = CheckDispense(amountMinorUnits);
        if (!check.Allowed)
        {
            _gate.Audit($"DISPENSE_BLOCKED requested={amountMinorUnits} reason={check.Reason}");
            return Synthetic(XfsConstants.WfsCmdCdmDispense, check.ResultCode);
        }

        var body = XfsStructures.BuildDispense(amountMinorUnits, present: present, cashUnitSelector: cashUnitSelector);
        var reply = _transport.Send(HService, XfsApi.Execute, XfsConstants.WfsCmdCdmDispense, "WFS_CMD_CDM_DISPENSE", body);
        _gate.Audit($"DISPENSE amount={amountMinorUnits} present={present} cu={cashUnitSelector} -> {reply.ResultName}");
        return reply;
    }

    /// <summary>
    /// Evaluates the three guardrails without writing a frame. Used by the
    /// exercise output and by the self test to prove that a refused dispense
    /// never reaches the service provider.
    /// </summary>
    public DispenseCheck CheckDispense(ulong amountMinorUnits)
    {
        if (amountMinorUnits > _policy.MaxDispenseMinorUnits)
            return new DispenseCheck(false, XfsConstants.WfsErrInvalidData,
                $"amount_over_ceiling {amountMinorUnits}>{_policy.MaxDispenseMinorUnits}");

        if (amountMinorUnits == 0)
            return new DispenseCheck(false, XfsConstants.WfsErrInvalidData, "zero_amount");

        if (!_policy.Window.Contains(DateTimeOffset.UtcNow))
            return new DispenseCheck(false, XfsConstants.WfsErrDeviceNotReady, "outside_service_window");

        if (!_gate.HasValidAcknowledgement(_policy.AcknowledgementPurpose, out var why))
            return new DispenseCheck(false, XfsConstants.WfsErrCommandRunning, $"no_acknowledgement ({why})");

        return new DispenseCheck(true, XfsConstants.WfsSuccess, "ok");
    }

    /// <summary>WFSExecute(WFS_CMD_CDM_PRESENT = 303): push prepared notes to the shutter.</summary>
    public XfsReply Present()
    {
        if (!_gate.HasValidAcknowledgement(_policy.AcknowledgementPurpose, out var why))
        {
            _gate.Audit($"PRESENT_BLOCKED reason=no_acknowledgement detail={why}");
            return Synthetic(XfsConstants.WfsCmdCdmPresent, XfsConstants.WfsErrCommandRunning);
        }
        var reply = _transport.Send(HService, XfsApi.Execute, XfsConstants.WfsCmdCdmPresent, "WFS_CMD_CDM_PRESENT", default);
        _gate.Audit($"CDM_CMD_PRESENT -> {reply.ResultName}");
        return reply;
    }

    /// <summary>WFSExecute(WFS_CMD_CDM_RETRACT = 305): pull presented notes back into the safe.</summary>
    public XfsReply Retract()
    {
        var reply = _transport.Send(HService, XfsApi.Execute, XfsConstants.WfsCmdCdmRetract, "WFS_CMD_CDM_RETRACT", default);
        _gate.Audit($"CDM_CMD_RETRACT -> {reply.ResultName}");
        return reply;
    }

    /// <summary>WFSExecute(WFS_CMD_CDM_RESET = 311): recover the device after an error.</summary>
    public XfsReply Reset()
    {
        var reply = _transport.Send(HService, XfsApi.Execute, XfsConstants.WfsCmdCdmReset, "WFS_CMD_CDM_RESET", default);
        _gate.Audit($"CDM_CMD_RESET -> {reply.ResultName}");
        return reply;
    }

    private static XfsReply Synthetic(int command, int result) => new()
    {
        Api = XfsApi.Execute,
        Command = command,
        Mnemonic = XfsConstants.ResultName(result),
        Result = result,
        Data = Array.Empty<byte>()
    };

    public void Dispose() => _transport.Dispose();
}

public readonly record struct DispenseCheck(bool Allowed, int ResultCode, string Reason);
