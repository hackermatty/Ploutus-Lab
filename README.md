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
    SelfTest.cs              28 assertions over guardrails, framing, forensics
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
covered by `selftest` (28/28 passing).

Not modelled, and not claimed:

* no `msxfs.dll` / vendor service provider, no `WFSOpen` handle negotiation;
* no NCR GBRU, Diebold Vynamic or Wincore Procash remote transport - the
  16-byte framing here is a lab contract, not a vendor protocol;
* the tail of `WFSCDMCASHUNIT` beyond the fields listed above is not parsed;
* `WFSCDMDISPENSE` is built for the amount/selector path only - the
  denomination-list path (`lpDenomination`) is not exercised;
* currency handling is minor-unit integer arithmetic with no rounding policy;
* the analyzer is heuristic - it reports evidence, not a verdict, and a clean
  trace does not prove a terminal is clean.

## 10. Using it on a real engagement

Swap `XfsTransport` for an adapter over the actual channel you are authorised to
test (a signed XFS client running on the terminal, or the vendor's documented
remote interface), keep `CdmClient`'s ordering of checks, and replace the
policy values with the engagement's agreed limits. Keep the audit file: the
difference between an authorised test and an incident is whether the dispense
calls are attributable.
