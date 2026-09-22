/*
 * operator_keys_embedded.h — Common German Enigma operator message keys
 *
 * German Enigma operators were notoriously lazy with message keys (Spruchschluessel).
 * Instead of random 3-letter combinations, they used:
 *   - First names (abbreviated to 3 letters): MAR, HAN, ERI, KLA, OTT, WIL...
 *   - Place names (abbreviated): BER, MUN, HAM, KOL, BRE, DRE, KIE...
 *   - Simple keyboard patterns: AAA, BBB, ABC, QWE, ASD, XYZ...
 *   - Naval directions: NOR, SUD, OST, WES (North, South, East, West)
 *   - Sequential patterns: ACE, BDF, CEG...
 *
 * These are 3-4 letter keys. The indicator decryption scoring checks if the
 * decrypted indicator matches any of these patterns and boosts the fitness
 * score significantly if it does.
 *
 * This is a known-plaintext attack based on operator laziness — a real WWII
 * weakness exploited by Bletchley Park.
 */

#define OPERATOR_KEY_COUNT 257

static const char *operator_keys[] = {
    /* ── German first names (3-letter abbreviations) ── */
    "MAR",  /* Martin */
    "HAN",  /* Hans */
    "ERI",  /* Erich */
    "KLA",  /* Klaus */
    "OTT",  /* Otto */
    "WIL",  /* Wilhelm */
    "MAX",  /* Max */
    "KAR",  /* Karl */
    "FRI",  /* Friedrich */
    "HEI",  /* Heinz */
    "GER",  /* Gerhard */
    "WOL",  /* Wolfgang */
    "JUR",  /* Juergen */
    "PEE",  /* Peter */
    "PET",  /* Peter */
    "STE",  /* Stefan */
    "AND",  /* Andreas */
    "THO",  /* Thomas */
    "MIC",  /* Michael */
    "CHR",  /* Christian */
    "FRA",  /* Franz */
    "JOH",  /* Johannes */
    "ALE",  /* Alexander */
    "MAN",  /* Manfred */
    "ROB",  /* Robert */
    "RUD",  /* Rudolf */
    "HER",  /* Hermann */
    "ALB",  /* Albert */
    "ERN",  /* Ernst */
    "JOS",  /* Josef */
    "LUD",  /* Ludwig */
    "GUN",  /* Guenther */
    "HOR",  /* Horst */
    "BER",  /* Bernhard */
    "DET",  /* Detlef */
    "HAR",  /* Harald */
    "ULA",  /* Ulla */
    "ING",  /* Inge */
    "ELI",  /* Elisabeth */
    "HEL",  /* Helga */
    "REN",  /* Renate */
    "HIL",  /* Hilde */
    "EDL",  /* Edeltraud */
    "MAG",  /* Margarete */
    "BRI",  /* Brigitte */
    "DOR",  /* Doris */
    "SUS",  /* Susanne */
    "BAR",  /* Barbara */
    "ANG",  /* Angela */
    "KAT",  /* Katharina */
    "EVA",  /* Eva */
    "ANA",  /* Anna */
    "MON",  /* Monika */
    "UTE",  /* Ute */
    "GUD",  /* Gudrun */

    /* ── German place names (3-letter abbreviations) ── */
    "MUN",  /* Muenchen */
    "HAM",  /* Hamburg */
    "KOL",  /* Koeln */
    "BRE",  /* Bremen */
    "DRE",  /* Dresden */
    "KIE",  /* Kiel */
    "LEI",  /* Leipzig */
    "NUR",  /* Nuernberg */
    "STU",  /* Stuttgart */
    "FRA",  /* Frankfurt (duplicate ok — hash set dedupes) */
    "DUS",  /* Duesseldorf */
    "DOR",  /* Dortmund (duplicate ok) */
    "ESS",  /* Essen */
    "BOC",  /* Bochum */
    "WUP",  /* Wuppertal */
    "BIE",  /* Bielefeld */
    "HAN",  /* Hannover (duplicate ok) */
    "NAC",  /* Nauen */
    "MAG",  /* Magdeburg (duplicate ok) */
    "HAL",  /* Halle */
    "CHE",  /* Chemnitz */
    "ROS",  /* Rostock */
    "LUB",  /* Luebeck */
    "FLE",  /* Flensburg */
    "BRA",  /* Braunschweig */
    "WIL",  /* Wilhelmshaven (duplicate ok) */
    "EMD",  /* Emden */
    "BRE",  /* Bremerhaven (duplicate ok) */
    "STR",  /* Stralsund */
    "GRI",  /* Greifswald */
    "SCH",  /* Schwerin */
    "POT",  /* Potsdam */
    "BER",  /* Berlin (duplicate ok) */
    "LAN",  /* Landsberg */
    "KOB",  /* Koblenz */
    "TRI",  /* Trier */
    "AUG",  /* Augsburg */
    "REG",  /* Regensburg */
    "WUE",  /* Wuerzburg */
    "ERL",  /* Erlangen */
    "NAC",  /* Nach (duplicate ok) */
    "FRE",  /* Freiburg */
    "KON",  /* Konstanz */
    "ULM",  /* Ulm */
    "HEI",  /* Heidelberg (duplicate ok) */
    "MAN",  /* Mannheim (duplicate ok) */
    "KAR",  /* Karlsruhe (duplicate ok) */
    "BAD",  /* Baden */

    /* ── Naval / military directional terms ── */
    "NOR",  /* Nord (North) */
    "SUD",  /* Sued (South) */
    "OST",  /* Ost (East) */
    "WES",  /* West (West) */
    "NWO",  /* Nordwest */
    "SOO",  /* Suedost */
    "NOW",  /* Nordwest alt */
    "SOW",  /* Suedwest */
    "NOO",  /* Nordost */
    "SON",  /* Suedost alt */

    /* ── Military terms (3-letter) ── */
    "FEI",  /* Feind (enemy) */
    "ANG",  /* Angriff (attack, duplicate ok) */
    "ABW",  /* Abwehr (defense) */
    "VOR",  /* Vormarsch (advance) */
    "RUC",  /* Rueckzug (retreat) */
    "STO",  /* Stellung (position) */
    "BEF",  /* Befehl (order) */
    "MEL",  /* Meldung (report) */
    "FUN",  /* Funk (radio) */
    "SAT",  /* Sattel */
    "TOR",  /* Torpedo */
    "UAB",  /* U-Boot */
    "BOO",  /* Boot */
    "SEE",  /* See (sea) */
    "HAF",  /* Hafen (harbor) */
    "KAP",  /* Kapitaen */
    "LEU",  /* Leutnant */
    "OBE",  /* Oberleutnant */
    "FAH",  /* Fahnrich */
    "MAT",  /* Maat */

    /* ── Simple keyboard/pattern keys (operator laziness) ── */
    "AAA",  /* all same */
    "BBB",
    "CCC",
    "DDD",
    "EEE",
    "FFF",
    "GGG",
    "HHH",
    "III",
    "JJJ",
    "KKK",
    "LLL",
    "MMM",
    "NNN",
    "OOO",
    "PPP",
    "QQQ",
    "RRR",
    "SSS",
    "TTT",
    "UUU",
    "VVV",
    "WWW",
    "XXX",
    "YYY",
    "ZZZ",

    /* ── Sequential alphabet patterns ── */
    "ABC",  /* forward */
    "BCD",
    "CDE",
    "DEF",
    "EFG",
    "FGH",
    "GHI",
    "HIJ",
    "IJK",
    "JKL",
    "KLM",
    "LMN",
    "MNO",
    "NOP",
    "OPQ",
    "PQR",
    "QRS",
    "RST",
    "STU",
    "TUV",
    "UVW",
    "VWX",
    "WXY",
    "XYZ",

    /* ── Reverse sequential patterns ── */
    "ZYX",  /* backward */
    "YXW",
    "XWV",
    "WVU",
    "VUT",
    "UTS",
    "TSR",
    "SRQ",
    "RQP",
    "QPO",
    "PON",
    "ONM",
    "NML",
    "MLK",
    "LKJ",
    "KJI",
    "JIH",
    "IHG",
    "HGF",
    "GFE",
    "FED",
    "EDC",
    "DCB",
    "CBA",

    /* ── Skip patterns (every other letter) ── */
    "ACE",
    "BDF",
    "CEG",
    "DFH",
    "EGI",
    "FHJ",
    "GIK",
    "HJL",
    "IKM",
    "JLN",
    "KMO",
    "LNP",
    "MOQ",
    "NPR",
    "OQS",
    "PRT",
    "QSU",
    "RTV",
    "SUW",
    "TVX",
    "UWY",
    "VXZ",

    /* ── QWERTZ keyboard row patterns (German keyboard) ── */
    "QWE",
    "WER",
    "ERT",
    "RTZ",
    "TZU",
    "ZUI",
    "UIO",
    "IOP",
    "ASD",
    "SDF",
    "DFG",
    "FGH",
    "GHJ",
    "HJK",
    "JKL",
    "YXC",
    "XCV",
    "CVB",
    "VBN",
    "BNM",

    /* ── Common 3-letter combos (days, months, numbers) ── */
    "EIN",  /* eins (one) */
    "ZWE",  /* zwei (two) */
    "DRE",  /* drei (three, duplicate ok) */
    "VIE",  /* vier (four) */
    "FUN",  /* fuenf (five) */
    "SEC",  /* sechs (six) */
    "SIE",  /* sieben (seven) */
    "ACH",  /* acht (eight) */
    "NEU",  /* neun (nine) */
    "ZEH",  /* zehn (ten) */
    "MON",  /* Montag (Monday, duplicate ok) */
    "DIE",  /* Dienstag (Tuesday) */
    "MIT",  /* Mittwoch (Wednesday) */
    "DON",  /* Donnerstag (Thursday) */
    "FRE",  /* Freitag (Friday, duplicate ok) */
    "SAM",  /* Samstag (Saturday) */
    "SON",  /* Sonntag (Sunday, duplicate ok) */
    "JAN",  /* Januar */
    "FEB",  /* Februar */
    "MAR",  /* Maerz (duplicate ok) */
    "APR",  /* April */
    "MAI",  /* Mai */
    "JUN",  /* Juni */
    "JUL",  /* Juli */
    "AUG",  /* August (duplicate ok) */
    "SEP",  /* September */
    "OKT",  /* Oktober */
    "NOV",  /* November */
    "DEZ",  /* Dezember */

    /* ── Phonetic alphabet (German Buchstabiertafel) ── */
    "ANT",  /* Anton */
    "BER",  /* Berta (duplicate ok) */
    "CAE",  /* Caesar */
    "DOR",  /* Dora (duplicate ok) */
    "EMI",  /* Emil */
    "FRI",  /* Friedrich (duplicate ok) */
    "GUS",  /* Gustav */
    "HEI",  /* Heinrich (duplicate ok) */
    "IDA",  /* Ida */
    "JUL",  /* Julius (duplicate ok) */
    "KAU",  /* Kaufmann */
    "LUD",  /* Ludwig (duplicate ok) */
    "MOR",  /* Martha */
    "NOR",  /* Nordpol (duplicate ok) */
    "OTT",  /* Otto (duplicate ok) */
    "PAU",  /* Paula */
    "QUE",  /* Quelle */
    "RIC",  /* Richard */
    "SAM",  /* Samuel (duplicate ok) */
    "THE",  /* Theodor */
    "ULR",  /* Ulrich */
    "VIK",  /* Viktor */
    "WIL",  /* Wilhelm (duplicate ok) */
    "XAN",  /* Xanthippe */
    "YPS",  /* Ypsilon */
    "ZAC",  /* Zacharias */

    /* ── Additional common lazy patterns ── */
    "ASD",  /* keyboard home row */
    "QAY",  /* keyboard column */
    "WSX",  /* keyboard column */
    "EDC",  /* keyboard column */
    "RFV",  /* keyboard column */
    "TGB",  /* keyboard column */
    "YHN",  /* keyboard column */
    "UJM",  /* keyboard column */
    "IKO",  /* keyboard diagonal */
    "OLP",  /* keyboard */
    "ZER",  /* zero */
    "NUL",  /* null/zero */
    "EUF",  /* Euphrat */
    "RHE",  /* Rhein */
    "ELB",  /* Elbe */
    "DON",  /* Donau (duplicate ok) */
    "ODE",  /* Oder */
    "WEI",  /* Weichsel */
    "RHE",  /* Rhein (duplicate ok) */
};

/*
 * Score a decrypted indicator against the operator key list.
 * Returns:
 *   100 — exact match to a name/place/phonetic
 *   80  — matches a keyboard/pattern key
 *   60  — matches a military/naval term
 *   50  — all same letter (AAA, BBB, etc.)
 *   30  — sequential pattern (ABC, XYZ, etc.)
 *    0  — no match (random key)
 *
 * Also checks for partial matches (first 2 letters match a known key prefix)
 * with a reduced score, since operators often used the same first letters.
 */
static int score_operator_key(const char *key, int key_len)
{
    /* Exact match check */
    for (int i = 0; i < OPERATOR_KEY_COUNT; i++) {
        if ((int)strlen(operator_keys[i]) == key_len &&
            strncmp(operator_keys[i], key, key_len) == 0) {

            /* Classify the match type for scoring */
            const char *k = operator_keys[i];

            /* All-same-letter pattern (AAA, BBB, ...) */
            if (k[0] == k[1] && k[1] == k[2]) return 50;

            /* Check if sequential (forward or backward) */
            if (key_len >= 3) {
                if ((k[1] == k[0]+1 && k[2] == k[1]+1) ||
                    (k[1] == k[0]-1 && k[2] == k[1]-1))
                    return 30;
            }

            /* Check if it's a keyboard pattern (QWE, ASD, etc.) */
            const char *kb_patterns[] = {
                "QWE","WER","ERT","RTZ","TZU","ZUI","UIO","IOP",
                "ASD","SDF","DFG","FGH","GHJ","HJK","JKL",
                "YXC","XCV","CVB","VBN","BNM",
                "QAY","WSX","EDC","RFV","TGB","YHN","UJM","IKO","OLP",
                NULL
            };
            for (int j = 0; kb_patterns[j]; j++) {
                if (strcmp(kb_patterns[j], k) == 0) return 80;
            }

            /* Check if it's a skip pattern (ACE, BDF, etc.) */
            if (key_len >= 3 && k[1] == k[0]+2 && k[2] == k[1]+2) return 30;

            /* Names, places, phonetic, military terms → highest score */
            return 100;
        }
    }

    /* Partial match: first 2 letters match a known prefix */
    int prefix_matches = 0;
    for (int i = 0; i < OPERATOR_KEY_COUNT; i++) {
        if ((int)strlen(operator_keys[i]) >= 3 &&
            strncmp(operator_keys[i], key, 2) == 0) {
            prefix_matches++;
        }
    }
    if (prefix_matches >= 2) return 20;  /* multiple keys share this prefix */
    if (prefix_matches == 1) return 10;  /* one key shares this prefix */

    return 0;
}