from __future__ import annotations

# https://www.freedesktop.org/software/ModemManager/doc/1.24.2/ModemManager/ModemManager-Flags-and-Enumerations.html
# https://github.com/openshine/ModemManager/blob/master/include/ModemManager-enums.h

MODEM_STATE: dict[int, str] = {
                                -1: "failed",       0: "unknown",       1: "initializing",
                                2: "locked",       3: "disabled",      4: "disabling",
                                5: "enabling",     6: "enabled",       7: "searching",
                                8: "registered",   9: "disconnecting", 10: "connecting",
                                11: "connected",
}
MODEM_STATE_FAILED_REASON: dict[int, str] = {
    0: "none", 1: "unknown", 2: "sim-missing", 3: "sim-error",
}

MODEM_LOCK: dict[int, str] = {
    0: "unknown",  1: "none",         2: "sim-pin",      3: "sim-pin2",
    4: "sim-puk",  5: "sim-puk2",     6: "ph-sp-pin",    7: "ph-sp-puk",
    8: "ph-net-pin", 9: "ph-net-puk", 10: "ph-sim-pin",  11: "ph-corp-pin",
    12: "ph-corp-puk", 13: "ph-fsim-pin", 14: "ph-fsim-puk",
    15: "ph-netsub-pin", 16: "ph-netsub-puk",
}

MODEM_ACCESS_TECHNOLOGY: dict[int, str] = {
    0: "unknown",   1: "pots",      2: "gsm",       4: "gsm-compact",
    8: "gprs",      16: "edge",     32: "umts",     64: "hsdpa",
    128: "hsupa",   256: "hspa",    512: "hspa-plus", 1024: "1xrtt",
    2048: "evdo0",  4096: "evdoa",  8192: "evdob",  16384: "lte",
    32768: "5gnr",
}

MODEM_3GPP_REGISTRATION_STATE: dict[int, str] = {
    0: "idle",          1: "home",          2: "searching",
    3: "denied",        4: "unknown",       5: "roaming",
    6: "home-sms-only", 7: "roaming-sms-only", 8: "emergency-only",
    9: "home-csfb-not-preferred", 10: "roaming-csfb-not-preferred",
    11: "attached-rlos",
}


def enum_str(value: int, table: dict[int, str]) -> str:
    return table.get(value, str(value))
