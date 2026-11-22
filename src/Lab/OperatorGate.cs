using System.Security.Cryptography;
using System.Text;

namespace PloutusLab.Xfs;

/// <summary>
/// Two-person rule for destructive CDM operations.
///
/// <para>
/// A dispense in this lab needs <see cref="DispensePolicy.RequiredApprovals"/>
/// distinct operator approvals inside the TTL. Each approval is an HMAC over
/// (operator id, purpose, expiry) keyed with a per-run secret, so an approval
/// cannot be replayed into another run, another purpose, or a later window.
/// </para>
///
/// <para>
/// The point of the exercise: Ploutus-family ATM malware has no such check.
/// Its whole value to an attacker is that one process can call dispense
/// repeatedly. Modelling the gate here is what makes the clone a *test
/// harness* instead of malware - removing or weakening it is the finding you
/// are looking for when you assess real ATM estates.
/// </para>
/// </summary>
public sealed class OperatorGate : IOperatorGate
{
    private readonly byte[] _runSecret;
    private readonly List<Approval> _approvals = new();
    private readonly object _lock = new();
    private readonly string _auditPath;
    private readonly int _requiredApprovals;
    private readonly TimeSpan _ttl;

    public OperatorGate(string auditPath, int requiredApprovals, TimeSpan ttl)
    {
        _auditPath = auditPath;
        _requiredApprovals = requiredApprovals;
        _ttl = ttl;
        _runSecret = RandomNumberGenerator.GetBytes(32);
    }

    /// <summary>Issues an approval token for one operator. Call once per approver.</summary>
    public ApprovalToken Grant(string operatorId, string purpose)
    {
        if (string.IsNullOrWhiteSpace(operatorId))
            throw new ArgumentException("operator id required", nameof(operatorId));

        var expires = DateTimeOffset.UtcNow.Add(_ttl);
        var token = Sign(operatorId, purpose, expires);
        lock (_lock)
        {
            // A new grant for the same operator supersedes the previous one,
            // so an operator cannot count twice by spamming approvals.
            _approvals.RemoveAll(a => a.OperatorId == operatorId && a.Purpose == purpose);
            _approvals.Add(new Approval(operatorId, purpose, expires, token));
        }
        Audit($"ACK_GRANTED operator={operatorId} purpose={purpose} expires={expires:O}");
        return new ApprovalToken(operatorId, purpose, expires, token);
    }

    public bool HasValidAcknowledgement(string purpose, out string reason)
    {
        lock (_lock)
        {
            var now = DateTimeOffset.UtcNow;
            _approvals.RemoveAll(a => a.Expires < now);

            var valid = _approvals
                .Where(a => a.Purpose == purpose)
                .Where(a => a.Token.Length == 64 &&
                            CryptographicOperations.FixedTimeEquals(
                                Convert.FromHexString(a.Token), Convert.FromHexString(Sign(a.OperatorId, a.Purpose, a.Expires))))
                .Select(a => a.OperatorId)
                .Distinct()
                .ToList();

            if (valid.Count >= _requiredApprovals)
            {
                reason = $"ok ({valid.Count} approvals: {string.Join(",", valid)})";
                return true;
            }

            reason = $"{valid.Count}/{_requiredApprovals} valid approvals";
            return false;
        }
    }

    public void Audit(string line)
    {
        var stamp = DateTimeOffset.UtcNow.ToString("O");
        var entry = $"{stamp} {line}";
        lock (_lock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_auditPath)!);
            File.AppendAllText(_auditPath, entry + Environment.NewLine);
        }
    }

    private string Sign(string operatorId, string purpose, DateTimeOffset expires)
    {
        var payload = Encoding.UTF8.GetBytes($"{operatorId}|{purpose}|{expires.ToUnixTimeSeconds()}");
        using var hmac = new HMACSHA256(_runSecret);
        return Convert.ToHexString(hmac.ComputeHash(payload)).ToLowerInvariant();
    }

    private sealed record Approval(string OperatorId, string Purpose, DateTimeOffset Expires, string Token);
}

public interface IOperatorGate
{
    bool HasValidAcknowledgement(string purpose, out string reason);
    void Audit(string line);
}

public sealed record ApprovalToken(string OperatorId, string Purpose, DateTimeOffset Expires, string Signature);
