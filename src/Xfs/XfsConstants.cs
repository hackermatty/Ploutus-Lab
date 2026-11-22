namespace PloutusLab.Xfs;

/// <summary>
/// CEN/XFS identifier space used by the reference implementation.
///
/// The numeric values are NOT free-form. They are assigned by the CEN/XFS
/// specification (CWA 16926 series) and each service class owns a numeric
/// window: the class number times 100. Within a window, info commands and
/// execute commands have their own offsets.
///
///   CDM (Cash Dispenser Module)  -> class 3, window 900..999
///   CIM (Cash-In Module)         -> class 13, window 1300..1399
///   IDC (Card Reader)            -> class 9, window 900..999 for IDC
///
/// The authoritative source is the C header shipped with each vendor's
/// runtime (msxfs.h). Two independent copies of the header are quoted in the
/// project README so the values below can be checked without trusting this file.
/// </summary>
public static class XfsConstants
{
    // ---------------------------------------------------------------------
    // Service classes
    // ---------------------------------------------------------------------
    public const int ServiceClassCdm = 3;
    public const int ServiceClassCim = 13;
    public const int ServiceClassIdc = 9;
    public const int ServiceClassPin = 6;
    public const int ServiceClassSi = 14;

    public static int ServiceOffset(int serviceClass) => serviceClass * 100;

    // ---------------------------------------------------------------------
    // Cash Dispenser Module (CDM), class 3 -> offset 300
    // ---------------------------------------------------------------------
    public const int CdmServiceOffset = ServiceClassCdm * 100;          // 300

    // Info commands
    public const int WfsInfCdmStatus           = CdmServiceOffset + 1;   // 301
    public const int WfsInfCdmCapabilities     = CdmServiceOffset + 2;   // 302
    public const int WfsInfCdmCashUnitInfo     = CdmServiceOffset + 3;   // 303
    public const int WfsInfCdmCurrencyExp      = CdmServiceOffset + 6;   // 306

    // Execute commands
    public const int WfsCmdCdmDenominate       = CdmServiceOffset + 1;   // 301
    public const int WfsCmdCdmDispense         = CdmServiceOffset + 2;   // 302
    public const int WfsCmdCdmPresent          = CdmServiceOffset + 3;   // 303
    public const int WfsCmdCdmReject           = CdmServiceOffset + 4;   // 304
    public const int WfsCmdCdmRetract          = CdmServiceOffset + 5;   // 305
    public const int WfsCmdCdmOpenShutter      = CdmServiceOffset + 6;   // 306
    public const int WfsCmdCdmCloseShutter     = CdmServiceOffset + 7;   // 307
    public const int WfsCmdCdmSetCashUnitInfo  = CdmServiceOffset + 8;   // 308
    public const int WfsCmdCdmReset            = CdmServiceOffset + 11;  // 311
    public const int WfsCmdCdmCount            = CdmServiceOffset + 12;  // 312
    public const int WfsCmdCdmPrepareDispense  = CdmServiceOffset + 26;  // 326
    public const int WfsCmdCdmSetBlacklist     = CdmServiceOffset + 27;  // 327
    public const int WfsCmdCdmGetFlag          = CdmServiceOffset + 31;  // 331
    public const int WfsCmdCdmSetFlag          = CdmServiceOffset + 32;  // 332

    // ---------------------------------------------------------------------
    // Cash-In Module (CIM), class 13 -> offset 1300
    // ---------------------------------------------------------------------
    public const int CimServiceOffset = ServiceClassCim * 100;          // 1300

    public const int WfsInfCimStatus           = CimServiceOffset + 1;  // 1301
    public const int WfsInfCimCapabilities     = CimServiceOffset + 2;  // 1302
    public const int WfsInfCimCashUnitInfo     = CimServiceOffset + 3;  // 1303

    // ---------------------------------------------------------------------
    // Card Reader (IDC), class 9 -> offset 900
    // ---------------------------------------------------------------------
    public const int IdcServiceOffset = ServiceClassIdc * 100;

    public const int WfsInfIdcStatus           = IdcServiceOffset + 1;
    public const int WfsCmdIdcReadRawData      = IdcServiceOffset + 4;
    public const int WfsCmdIdcEjectCard        = IdcServiceOffset + 13;

    // ---------------------------------------------------------------------
    // Result codes (WFS_RESULT). Only the subset used by this lab.
    // ---------------------------------------------------------------------
    public const int WfsSuccess                = 0;
    public const int WfsErrInvalidCommand      = -2;
    public const int WfsErrDeviceNotReady      = -12;
    public const int WfsErrInvalidData         = -29;
    public const int WfsErrUnsupportedCommand  = -43;
    public const int WfsErrNotSupported        = -129;
    public const int WfsErrServiceNotFound     = -133;
    public const int WfsErrCommandRunning      = -101;
    public const int WfsErrInternal            = -100;
    public const int WfsErrShutterOpen         = -406;
    public const int WfsErrInvalidCashUnit     = -403;
    public const int WfsErrNotesDispensed      = -404;
    public const int WfsErrCashUnitEmpty       = -405;
    public const int WfsErrTooManyItems        = -402;

    public static string ResultName(int code) => code switch
    {
        WfsSuccess               => "WFS_SUCCESS",
        WfsErrInvalidCommand     => "WFS_ERR_INVALID_COMMAND",
        WfsErrDeviceNotReady     => "WFS_ERR_DEV_NOT_READY",
        WfsErrInvalidData        => "WFS_ERR_INVALID_DATA",
        WfsErrUnsupportedCommand => "WFS_ERR_UNSUPP_COMMAND",
        WfsErrNotSupported       => "WFS_ERR_UNSUPP_DATA",
        WfsErrServiceNotFound    => "WFS_ERR_SERVICE_NOT_FOUND",
        WfsErrCommandRunning     => "WFS_ERR_CMD_RUNNING",
        WfsErrInternal           => "WFS_ERR_INTERNAL_ERROR",
        WfsErrShutterOpen        => "WFS_ERR_CDM_SHUTTER_NOT_CLOSED",
        WfsErrInvalidCashUnit    => "WFS_ERR_CDM_INVALIDCASHUNIT",
        WfsErrNotesDispensed     => "WFS_ERR_CDM_NOTESDISPENSED",
        WfsErrCashUnitEmpty      => "WFS_ERR_CDM_CASHUNITEMPTY",
        WfsErrTooManyItems       => "WFS_ERR_CDM_TOOMANYITEMS",
        _                        => $"WFS_ERR_UNKNOWN({code})"
    };

    // ---------------------------------------------------------------------
    // CDM dispense flags
    // ---------------------------------------------------------------------
    public const ushort CdmDispensePresent   = 0x0001; // bPresent
    public const ushort CdmDispenseNoPresent = 0x0000;
}
