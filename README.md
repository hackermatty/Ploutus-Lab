# ploutus-lab

A CEN/XFS cash-dispenser harness for testing and detecting Ploutus-class ATM
malware behaviour, built as a normal .NET 8 project.

It is a **harness**, not a weaponised sample. Every dispense path is capped,
time-boxed, two-person approved and audited, and the only endpoint it can talk
to is a loopback service it starts itself. That is a deliberate design choice,
not a limitation of the code: a turnkey reimplementation of Ploutus would be a
binary that detonates the first time it touches a production estate, and it
would teach nothing that this project does not teach more precisely.

---

## 1. What Ploutus actually is

Ploutus is a family of ATM malware that appeared around 2013 and has been
maintained and resold since. The public analyses (Kaspersky 2016/2017,
Group-IB, Team Cymru, and the 2017 Ploutus-D write-ups) agree on the core:

| Element | What the family does |
|---|---|
| Execution surface | Runs on the ATM's Windows host, usually in the interactive kiosk session |
| Dispense primitive | Calls the CEN/XFS API directly - `WFSOpen` on the CDM service, then `WFSExecute(WFS_CMD_CDM_DISPENSE)` |
| Why it works | XFS does not authenticate the calling process. Any code running as the kiosk user that can load `msxfs.dll` can ask the dispenser for money |
| Interface | Ploutus-D shipped a numeric-keypad UI (special key sequence) or a TCP listener; later variants added a controller/C2 model |
| Notable trick | Ploutus-D replaced/loaded a rogue `msxfs.dll` next to the application, so the malicious code inherited the application's XFS session |
| Detection angle | A dispense with no card read and no PIN entry in the same session, or a burst of dispenses above the terminal's fast-cash limit |

The transferable facts are therefore: **the XFS command numbers and structs**,
**the state machine the dispenser expects**, and **what the trace looks like
when something bypasses that state machine**. This project implements exactly
those three things and nothing that would let it drain a real cassette.

## 2. Why not a byte-for-byte clone

A faithful reimplementation would need a genuine vendor service provider
(`msxfs.dll` plus the NCR/Diebold/Wincore SP) and a live dispenser. Neither can
be shipped, and the resulting binary would only be useful against a machine you
do not own. What *can* be shipped, and what actually gets used during an
assessment, is:

* a correct model of the XFS identifiers and message layout, so a client you
  write against it is structurally right;
* a policy layer that shows where a real deployment should have put its
  authorisation checks;
* a forensic scorer that turns a vendor log into per-rule evidence;
* a hardening baseline that maps each technique to the control that stops it.

## 3. Layout

```
PloutusLab.csproj
src/
  Program.cs                 CLI: exercise | serve | analyze | audit | selftest | constants
  Xfs/
    XfsConstants.cs          CEN/XFS service classes, command ids, result codes
    XfsStructures.cs         WFSCDMDISPENSE + LPWFSCDMCASHUNITINFO wire layout
    CdmClient.cs             typed CDM wrapper; enforces the dispense policy
  Protocol/
    XfsTransport.cs          framed request/response transport (GetInfo vs Execute)
    LabBus.cs                loopback XFS endpoint + in-memory cassette safe
  Lab/
    DispensePolicy.cs        ceiling, window, approval requirements
    OperatorGate.cs          HMAC approval tokens, append-only audit
    Scenario.cs              end-to-end exercise and serve mode
    SelfTest.cs              30 assertions over guardrails, framing, forensics
  Forensics/
    XfsLogAnalyzer.cs        Ploutus-behaviour scoring for vendor XFS logs
  Deploy/
    DeploymentAudit.cs       10-control ATM hardening baseline
examples/
  sample-xfs.log             a normal withdrawal followed by an attack session
```

## 4. Build and run

Requires the .NET 8 SDK.

```bash
dotnet build -c Release
dotnet run -c Release -- selftest
dotnet run -c Release -- exercise --amount 2000 --verbose
dotnet run -c Release -- analyze --file examples/sample-xfs.log --ceiling 20000
dotnet run -c Release -- audit --met ATM-01,ATM-04,ATM-10
```

Environment:

| Variable | Meaning |
|---|---|
| `PLOUTUS_MAX_MINOR` | hard ceiling in minor units (default 2000 = 20.00) |
| `PLOUTUS_WINDOW_START` / `_END` | ISO-8601 UTC exercise window |
| `PLOUTUS_AUDIT` | audit log path |
| `PLOUTUS_CURRENCY` | cassette set to load: `AUD`, `EUR`, `GBP` or `USD` (default `AUD`) |
| `PLOUTUS_OPERATORS` | comma-separated approvers for `serve` mode |

`serve` binds `127.0.0.1` only. There is no flag to change that; the listener
rejects any non-loopback peer at accept time.

## 5. The XFS contract this implements

CEN/XFS numbers each service class into a window of 100. The header shipped
with every vendor runtime (`msxfs.h`) is the authority:

```c
#define WFS_SERVICE_CLASS_CDM        (3)
#define CDM_SERVICE_OFFSET           (WFS_SERVICE_CLASS_CDM * 100)   /* 300 */

/* info */
#define WFS_INF_CDM_STATUS           (CDM_SERVICE_OFFSET + 1)        /* 301 / 0x012D */
#define WFS_INF_CDM_CAPABILITIES     (CDM_SERVICE_OFFSET + 2)        /* 302 */
#define WFS_INF_CDM_CASH_UNIT_INFO   (CDM_SERVICE_OFFSET + 3)        /* 303 / 0x012F */
#define WFS_INF_CDM_CURRENCY_EXP     (CDM_SERVICE_OFFSET + 6)

/* execute */
#define WFS_CMD_CDM_DENOMINATE       (CDM_SERVICE_OFFSET + 1)
#define WFS_CMD_CDM_DISPENSE         (CDM_SERVICE_OFFSET + 2)        /* 302 / 0x012E */
#define WFS_CMD_CDM_PRESENT          (CDM_SERVICE_OFFSET + 3)        /* 303 - collides */
#define WFS_CMD_CDM_RETRACT          (CDM_SERVICE_OFFSET + 5)
#define WFS_CMD_CDM_RESET            (CDM_SERVICE_OFFSET + 11)
```

The collision at 303 is real and is why `XfsTransport` carries an API selector
alongside the command: the service provider distinguishes `WFSGetInfo(303)`
from `WFSExecute(303)`, not the number. Getting this wrong is the classic
reason a from-scratch XFS client "works" for status and fails on present.

`WFSCDMDISPENSE` is modelled at its documented offsets, which is what matters
for interop:

| Offset | Field |
|---|---|
| `0x00` | `usTellerID` |
| `0x02` | `usMixNumber` |
| `0x04` | `fwPosition` |
| `0x06` | `bPresent` |
| `0x08` | `usTransaction` |
| `0x0A` | `ulAmount` (minimum dispense units) |
| `0x0E` | `usCount` |
| `0x10` | `lpDenomination` |
| `0x14` | `lpszExtra` |
| `0x18` | `ulTransactionID` |
| `0x1C` | `fwCashUnitSelector` |

The reply to `WFS_INF_CDM_CASH_UNIT_INFO` is a `usCount` followed by that many
`WFSCDMCASHUNIT` structs; the parser reads `ulCount` at `+0x0C` and `ulValue`
at `+0x20` per struct.

## 6. Where the guardrails live

`CdmClient.Dispense` calls `CheckDispense` **before** it writes a frame:

1. `MaxDispenseMinorUnits` - from configuration, not from the caller.
2. `Window.Contains(now)` - the exercise slot.
3. `OperatorGate.HasValidAcknowledgement` - N distinct operators, each with an
   HMAC-SHA256 token over `(operator, purpose, expiry)` keyed by a per-run
   secret, so approvals cannot be replayed across runs or purposes.

The same three checks are duplicated in `LabBus.Dispense`, i.e. at the device
boundary, so a client that speaks the raw framing - `serve` mode, a script, a
fuzzer - cannot skip them either. A refused dispense never reaches the cassette;
the self test asserts both layers, that the cassette does not move, and that the
refusal is audited. This is the
control that Ploutus-class malware lacks, and modelling it explicitly makes the
gap visible when you review a real terminal: if the ATM application exposes a
dispense callable outside its transaction controller, that is the finding.

## 7. Forensic rules

`ploutus-lab analyze` scores a vendor log for:

| Rule | Severity | Trigger |
|---|---|---|
| `dispense-without-card` | high | `WFS_CMD_CDM_DISPENSE` with no prior `WFS_CMD_IDC_READ_*` in session |
| `dispense-without-authorisation` | high | dispense with no prior `WFS_CMD_PIN_ENTRY` or `WFS_CMD_CIM_CASH_IN*` |
| `dispense-burst` | high | 3+ dispense attempts within 15 s |
| `dispense-over-fastcash-limit` | medium | `amount=` above the configured ceiling |
| `reset-storm` | medium | 3+ `WFS_CMD_CDM_RESET` in the window |
| `dispense-error` | info | `WFS_ERR_*` result on a dispense |

Session boundaries are inferred from `IDC_READ_*` / `IDC_EJECT_CARD`. Real logs
that carry a session id should key on that instead - see the comment in
`XfsLogAnalyzer`.

## 8. Hardening baseline

`ploutus-lab audit` renders ten controls (`ATM-01` .. `ATM-10`) with the reason
each one matters and a concrete verification step: allow-listing, dispense tied
to an open transaction, kiosk least privilege, SP DLL hash pinning, cassette
reconciliation, remote-management paths, egress filtering, Secure Boot/BitLocker,
off-terminal log shipping, and physical port/keypad controls.

## 9. Fidelity and limitations

Observed and verified in this repository: the identifier arithmetic, the
`WFSCDMDISPENSE` offsets, the GetInfo/Execute split, the policy enforcement
ordering, the inventory round trip, the log rules, and the audit log - all
covered by `selftest` (30/30 passing).

Not modelled, and not claimed:

* no `msxfs.dll` / vendor service provider, no `WFSOpen` handle negotiation;
* no NCR GBRU, Diebold Vynamic or Wincore Procash remote transport - the
  16-byte framing here is a lab contract, not a vendor protocol;
* the tail of `WFSCDMCASHUNIT` beyond the fields listed above is not parsed;
* `WFSCDMDISPENSE` is built for the amount/selector path only - the
  denomination-list path (`lpDenomination`) is not exercised;
* currency handling is minor-unit integer arithmetic with fixed note ladders for
  the four supported codes and no rounding or FX policy;
* the analyzer is heuristic - it reports evidence, not a verdict, and a clean
  trace does not prove a terminal is clean.

## 10. Using it on a real engagement

The modes are ordered by how much they touch. Work down the list and stop as
soon as you have the answer: log analysis and the audit checklist need no
access to a terminal, and only the last mode can move cash.

### 10.1 Before anything runs

The guardrails are only as good as the paperwork behind them.

* **Scope in writing, naming the estate.** The amount, the window and the two
  approver names in the authorisation should be the exact values you put in
  `PLOUTUS_MAX_MINOR`, `PLOUTUS_WINDOW_START`/`_END` and `PLOUTUS_OPERATORS`.
  If the letter says one thing and the environment another, the exercise is
  testing something nobody approved.
* **Two named people, both present.** The gate needs two distinct approvals and
  the audit log records the ids, so the log becomes the record of who
  authorised what.
* **Cash-in-transit and the terminal owner notified.** A successful dispense is
  a physical event. State which cassette and how much beforehand, or the
  reconciliation afterwards becomes an incident.
* **Baseline hashes captured.** SHA-256 of `msxfs.dll` and every vendor service
  provider DLL, plus the XFS journal path and its rotation window. That
  baseline is what ATM-04 is scored against later.
* **A clock you trust.** The window check uses local `UtcNow`, so a drifting
  laptop fails closed with `outside_service_window` rather than dispensing.

### 10.2 Which mode answers which question

| Mode | Reaches | Risk to the estate | Use it for |
|---|---|---|---|
| `analyze` | a log file | none (read only) | first pass on any trace you already hold |
| `audit` | nothing | none (prints a checklist) | scoping an estate, writing findings |
| `exercise` | loopback + in-memory safe | none (synthetic cassette) | training, validating your model of the flow |
| `serve` + adapter | a real dispenser | cash moves | only under signed change control |

Two properties make `exercise` safe to hand to a junior analyst: the cassette is
in memory (`LabBus`), and the requested amount is clamped rather than trusted -
`Scenario` dispenses `Math.Min(amount, ceiling)`, so `--amount 500000` cannot
exceed the configured ceiling even if someone asks it to.

### 10.3 Configuration for the engagement

| Variable | Set it to |
|---|---|
| `PLOUTUS_MAX_MINOR` | the agreed per-dispense ceiling, in minor units |
| `PLOUTUS_WINDOW_START` / `_END` | the change window, ISO-8601 UTC, wider than the run |
| `PLOUTUS_ACK_PURPOSE` | a per-engagement string, e.g. `atm-04-validation` |
| `PLOUTUS_AUDIT` | a path outside `bin/`, e.g. `~/engagements/<client>/audit.log` |
| `PLOUTUS_OPERATORS` | the two named approvers, for `serve` only |

`PLOUTUS_ACK_PURPOSE` is read by `DispensePolicy.FromEnvironment` but is not in
the section 4 table. Set it distinctly per engagement: the HMAC covers
`(operator, purpose, expiry)`, so a token minted for one job cannot satisfy
another even if the log is replayed.

Keep `PLOUTUS_AUDIT` outside the build output. The default lands under
`AppContext.BaseDirectory`, where a `dotnet clean` would delete the audit trail.

### 10.4 Exit codes before you script anything

| Exit | Command | Meaning |
|---|---|---|
| 0 | `selftest` | every assertion passed |
| 1 | `selftest` | at least one assertion failed |
| 0 | `exercise` | the dispense returned `WFS_SUCCESS` |
| 2 | `exercise` | the dispense was refused or failed (a valid result, not an error) |
| 0 | `analyze` | no high-severity findings |
| 1 | `analyze` | at least one high-severity finding |
| 0 | `audit` | all ten controls marked met |
| 1 | `audit` | at least one control not met, i.e. almost always |
| 64 | any | usage error: bad flag, or `--file` missing |
| 70 | any | unhandled exception |

`analyze` and `audit` use a non-zero exit as a *finding*, not a failure. Put
`analyze` in a pipeline as a gate if that suits you, but do not let `audit`
break a build: it returns 1 until all ten controls are met.

### 10.5 Working from logs, without touching a terminal

Start here. It needs a trace the operator can export for you and nothing else.

```bash
ploutus-lab analyze --file <terminal>-2026-11-20.log --ceiling 50000
```

* **Calibrate `--ceiling` first.** `dispense-over-fastcash-limit` is only
  meaningful against the terminal's real fast-cash limit; a guessed value
  produces findings you cannot defend. Ask the operator for it.
* **Baseline a known-good terminal.** Run the analyzer over a quiet day on a
  terminal with no suspected activity, so "normal" is defined by data rather
  than by assumption. Findings from the suspect terminal are then a delta.
* **Read it as evidence, not a verdict.** The rules in section 7 are heuristic,
  and session boundaries are inferred from `IDC_READ_*` / `IDC_EJECT_CARD`. A
  log that carries a real session id should be keyed on that instead, as the
  comment in `XfsLogAnalyzer` says.

### 10.6 Scoring the estate against the baseline

```bash
ploutus-lab audit --met ATM-01,ATM-06,ATM-09 > audit-ATM-01.txt
```

Each unmet control is one finding, and the `test:` line is the verification step
to put in it. The rendered output is the deliverable; keep it with the report so
the client can re-run it after remediation and compare.

### 10.7 Exercising against a real terminal

Only with signed change control, and only after the two sections above have told
you it is worth doing.

**The transport needs a small refactor first.** Earlier revisions of this
README said to "swap `XfsTransport` for an adapter", but `XfsTransport` is a
`sealed` class and `CdmClient` takes it concretely, so there is nothing to
substitute.

Extract the interface over `Send`, then implement it over the channel you are
authorised to use (a signed XFS client on the terminal, or the vendor's
documented remote interface):

```csharp
public interface IXfsTransport : IDisposable
{
    XfsReply Send(ushort hService, XfsApi api, int command, string mnemonic, ReadOnlySpan<byte> body);
}
```

That is three edits: add the interface, mark `XfsTransport : IXfsTransport`,
and change `CdmClient`'s field and constructor parameter to `IXfsTransport`.
This compiles with no warnings and the self test still passes 28/28, so the
refactor costs nothing but has to happen before an adapter exists.

**Keep the check ordering.** `CdmClient.Dispense` calls `CheckDispense` before it
writes a frame: ceiling, then window, then acknowledgement. An adapter that
moves that policy into the adapter, or behind it, has removed the only thing
that makes this a harness.

**Do not try to expose `serve`.** It binds `127.0.0.1` and refuses a
non-loopback peer at accept time. If your test client runs on another host, use
an SSH tunnel (`ssh -L 18500:127.0.0.1:18500 <jump>`): the tool then sees a
loopback peer, which is the only configuration it will talk to.

**Note what `serve` does and does not prove.** Approvals are pre-seeded from
`PLOUTUS_OPERATORS`, so a successful dispense demonstrates that the policy path
works, not that two humans approved it. The two-person property is only real in
`exercise` mode, where `Grant` is called twice at run time.

### 10.8 Evidence to capture

* the audit log from `PLOUTUS_AUDIT`, hashed and stored off the device - the same
  discipline ATM-09 asks of the client's own XFS journal;
* `exercise --verbose` output, which includes the lab bus trace with the API,
  command, byte count and result for every frame;
* cash-unit inventory before and after, plus the reconciliation delta;
* the operator ids and UTC timestamps the run used.

Keep the **refused** lines. An entry like
`DISPENSE_BLOCKED requested=2001 reason=amount_over_ceiling` is the proof that
the control exists and fired, which is the actual finding.

### 10.9 Hand-back

Stop `serve`, confirm the cassette reconciles against what was dispensed, remove
any adapter build from the terminal, restore the configuration you changed, and
unset the `PLOUTUS_*` variables. The audit log names operators and timestamps,
so treat it as client-confidential and hand it over rather than leaving it on
the laptop.

### 10.10 Turning controls into findings

The three that matter most for this family, with the evidence that carries them:

| Control | Finding | Evidence |
|---|---|---|
| ATM-02 | dispense callable outside the transaction state machine | the application's XFS wrapper exposes `WFSExecute(WFS_CMD_CDM_DISPENSE)` as a method reachable from anywhere in the process |
| ATM-04 | XFS service provider chain not integrity-checked | SHA-256 of `msxfs.dll`/SP drift from the vendor manifest, with no alerting on the drift |
| ATM-09 | dispense-without-card not detectable | the XFS journal never leaves the terminal, or the SIEM has no rule for `WFS_CMD_CDM_DISPENSE` without a preceding `WFS_CMD_PIN_ENTRY` |

The difference between an authorised test and an incident is whether the
dispense calls are attributable. That is what the audit file is for.
