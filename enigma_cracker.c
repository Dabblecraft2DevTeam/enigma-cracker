/*
 * enigma_cracker.c — Enigma M3/M4 simulator + brute-force cracker
 *
 * Implements:
 *   - Full Enigma M3 (3-rotor) and M4 (4-rotor Naval) machines
 *   - All standard rotors I–VIII, beta, gamma; reflectors B, C, B_thin, C_thin
 *   - Plugboard
 *   - Index of Coincidence fitness function
 *   - German trigram/bigram scoring
 *   - Brute force: all rotor perms × positions × ring settings for M3
 *   - Hill climbing on plugboard for top candidates
 *   - Indicator-based message key recovery (M3 doubled indicator, M4 derivation)
 *   - U-264 M4 ciphertext decryption (known settings verification)
 *   - Self-test: encrypt a known message, then brute-forces it from ciphertext only
 *   - CLI interface for external callers (GUI, scripts)
 *   - JSON output mode for machine parsing
 *
 * Build:  gcc -O3 -fopenmp -o enigma_cracker enigma_cracker.c -lm
 * Run:    ./enigma_cracker                              # self-test mode
 *         ./enigma_cracker --ct CIPHERTEXT --mode M3     # crack M3
 *         ./enigma_cracker --ct CIPHERTEXT --mode M4     # crack M4
 *         ./enigma_cracker --ct CIPHERTEXT --mode M3 --indicator ABCDEF
 *         ./enigma_cracker --ct CIPHERTEXT --mode M3 --format json
 *         echo CIPHERTEXT | ./enigma_cracker --stdin --mode M4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#ifdef _OPENMP
#include <omp.h>
#endif
#include "german_words_embedded.h"  /* Embedded German word list fallback */
#include "operator_keys_embedded.h" /* Common German operator message keys */

/* ────────────────────────────────────────────────────────── */
/*  Cross-platform timing                                      */
/* ────────────────────────────────────────────────────────── */

#ifdef _WIN32
#include <windows.h>
static double now_sec(void) {
    static LARGE_INTEGER freq = {0};
    if (freq.QuadPart == 0)
        QueryPerformanceFrequency(&freq);
    LARGE_INTEGER count;
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
}
#else
#include <sys/time.h>
static double now_sec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}
#endif

/* ────────────────────────────────────────────────────────── */
/*  Rotor and reflector data                                  */
/* ────────────────────────────────────────────────────────── */

/* Rotor wirings (A=0 … Z=25), stored as strings for readability */
static const char *ROTOR_WIRE[] = {
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ",  /* I    */
    "AJDKSIRUXBLHWTMCQGZNPYFVOE",  /* II   */
    "BDFHJLCPRTXVZNYEIWGAKMUSQO",  /* III  */
    "ESOVPZJAYQUIRHXLNFTGKDCMWB",  /* IV   */
    "VZBRGITYUPSDNHLXAWMJQOFECK",  /* V    */
    "JPGVOUMFYQBENHZRDKASXLICTW",  /* VI   */
    "NZJHGRCXMYSWBOUFAIVBLPEKQD",  /* VII  */
    "FKQHTLXOCBJSPDZRAMEWNIUYGV",  /* VIII */
    "LEYJVCNIXWPBQMDRTAKZGFUHOS",  /* beta  */
    "FSOKANUERHMBTIYCWLQPZXVGDJ",  /* gamma */
};

static const char *ROTOR_NAME[] = {
    "I","II","III","IV","V","VI","VII","VIII","beta","gamma"
};

/* Notch positions (Q=16, E=4, V=21, J=9, Z=25, M=12); –1 = none */
static const int ROTOR_NOTCH[10][2] = {
    {16,-1},  /* I    Q  */
    { 4,-1},  /* II   E  */
    {21,-1},  /* III  V  */
    { 9,-1},  /* IV   J  */
    {25,-1},  /* V    Z  */
    {25,12},  /* VI   Z,M */
    {25,12},  /* VII  Z,M */
    {25,12},  /* VIII Z,M */
    { -1,-1},  /* beta   */
    { -1,-1},  /* gamma  */
};

static const char *REFLECTOR_WIRE[] = {
    "YRUHQSLDPXNGOKMIEBFZCWVJAT",  /* B       */
    "FVPJIAOYEDRZXWGCTKUQSBNMHL",  /* C       */
    "ENKQAUYWJICOPBLMDXZVFTHRGS",  /* B_thin  */
    "RDOBJNTKVEHMLFCWZAXGYIPSUQ",  /* C_thin  */
};

static const char *REFLECTOR_NAME[] = {"B","C","B_thin","C_thin"};

enum { R_I=0, R_II, R_III, R_IV, R_V, R_VI, R_VII, R_VIII, R_BETA, R_GAMMA };
enum { REF_B=0, REF_C, REF_B_THIN, REF_C_THIN };

/* ────────────────────────────────────────────────────────── */
/*  Precomputed tables                                        */
/* ────────────────────────────────────────────────────────── */

static int rfwd[10][26];   /* forward wiring  */
static int rbwd[10][26];   /* backward (inverse) wiring */
static int rnotch[10][26]; /* 1 = position is a notch  */
static int refw[4][26];    /* reflector wiring */

/* German trigram score table: trigram_score[a][b][c] */
static int tri_score[26][26][26];

/* ────────────────────────────────────────────────────────── */
/*  German dictionary hash set                                  */
/* ────────────────────────────────────────────────────────── */

#define DICT_HASH_SIZE 262144   /* power of 2, ~256K slots */
#define DICT_MAX_WORD   32      /* max word length we store */

static char  *dict_slots[DICT_HASH_SIZE];  /* heap-allocated word strings */
static int    dict_count = 0;
static int    dict_loaded = 0;   /* 1 = dictionary file was loaded */

/* FNV-1a hash, masked to table size */
static unsigned dict_hash(const char *word, int len)
{
    unsigned h = 2166136261u;
    for (int i = 0; i < len; i++) {
        h ^= (unsigned char)word[i];
        h *= 16777619u;
    }
    return h & (DICT_HASH_SIZE - 1);
}

/* Insert a word into the hash set (open addressing, linear probe) */
static void dict_insert(const char *word)
{
    int len = (int)strlen(word);
    if (len < 3 || len >= DICT_MAX_WORD) return;

    unsigned h = dict_hash(word, len);
    for (int i = 0; i < DICT_HASH_SIZE; i++) {
        unsigned idx = (h + i) & (DICT_HASH_SIZE - 1);
        if (!dict_slots[idx]) {
            dict_slots[idx] = strdup(word);
            dict_count++;
            return;
        }
        if (strcmp(dict_slots[idx], word) == 0)
            return;  /* already present */
    }
    /* table full — shouldn't happen with 256K slots and ~3K words */
}

/* Check if a word exists in the dictionary (open addressing lookup) */
static int dict_contains(const char *word, int len)
{
    if (len < 3 || len >= DICT_MAX_WORD) return 0;

    unsigned h = dict_hash(word, len);
    for (int i = 0; i < DICT_HASH_SIZE; i++) {
        unsigned idx = (h + i) & (DICT_HASH_SIZE - 1);
        if (!dict_slots[idx])
            return 0;  /* empty slot → not found */
        if ((int)strlen(dict_slots[idx]) == len &&
            strncmp(dict_slots[idx], word, len) == 0)
            return 1;
    }
    return 0;
}

/* Load german_words.txt from the given path. Returns number of words loaded. */
static int load_german_dictionary(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[DICT_MAX_WORD];
    while (fgets(line, sizeof(line), f)) {
        /* strip whitespace, uppercase */
        int len = 0;
        for (int i = 0; line[i] && len < DICT_MAX_WORD - 1; i++) {
            char c = line[i];
            if (c >= 'a' && c <= 'z') c -= 32;
            if (c >= 'A' && c <= 'Z')
                line[len++] = c;
        }
        line[len] = '\0';
        if (len >= 3)
            dict_insert(line);
    }
    fclose(f);
    dict_loaded = 1;
    return dict_count;
}

/* Try to load dictionary from several candidate paths relative to the binary */
static void load_dictionary_auto(void)
{
    /* Try several locations:
     *   1. german_words.txt in the same directory as the executable
     *   2. ./german_words.txt (current working directory)
     *   3. /usr/local/share/enigma_cracker/german_words.txt
     */
    const char *paths[] = {
        "german_words.txt",
        "./german_words.txt",
        "/usr/local/share/enigma_cracker/german_words.txt",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        int n = load_german_dictionary(paths[i]);
        if (n > 0) {
            fprintf(stderr, "Loaded %d German dictionary words from %s\n", n, paths[i]);
            return;
        }
    }
    fprintf(stderr, "german_words.txt not found — using embedded word list (%d words)\n", EMBEDDED_WORD_COUNT);
    /* Load embedded words as fallback */
    for (int i = 0; i < EMBEDDED_WORD_COUNT; i++) {
        dict_insert(embedded_words[i]);
    }
    dict_loaded = 1;
}

static void init_tables(void)
{
    for (int r = 0; r < 10; r++) {
        for (int i = 0; i < 26; i++) {
            int j = ROTOR_WIRE[r][i] - 'A';
            rfwd[r][i] = j;
            rbwd[r][j] = i;
        }
        for (int i = 0; i < 26; i++) rnotch[r][i] = 0;
        if (ROTOR_NOTCH[r][0] >= 0) rnotch[r][ROTOR_NOTCH[r][0]] = 1;
        if (ROTOR_NOTCH[r][1] >= 0) rnotch[r][ROTOR_NOTCH[r][1]] = 1;
    }
    for (int r = 0; r < 4; r++)
        for (int i = 0; i < 26; i++)
            refw[r][i] = REFLECTOR_WIRE[r][i] - 'A';

    /* Zero the trigram table, then fill in common German trigrams */
    memset(tri_score, 0, sizeof(tri_score));
    struct { const char *t; int s; } tris[] = {
        {"EIN",100},{"ICH",90},{"NIC",80},{"UND",85},{"DIE",75},
        {"SCH",70},{"IST",65},{"DER",60},{"UNG",55},{"DEN",50},
        {"ACH",45},{"ENE",40},{"TEN",50},{"GEN",45},{"NES",40},
        {"BER",40},{"STE",40},{"TER",35},{"HEN",35},{"ABE",30},
        {"ERE",30},{"ANI",30},{"RUN",30},{"END",35},{"ITE",30},
        {"NUN",25},{"AUS",30},{"EIT",25},{"VER",35},{"NST",25},
        {"RIC",30},{"TIC",25},{"HAB",25},{"WIR",25},{"KAN",25},
        {"WUR",25},{"ZUR",25},{"CHE",45},{"IND",30},{"NCH",60},
        {"AUC",25},{"NOC",25},{"SIC",25},{"ANG",25},{"MAR",20},
        {"RIF",20},{"EHE",20},{"TAT",20},{"IGE",20},{"REN",35},
        {"ENC",25},{"ATT",20},{"ION",20},{"LEI",20},{"TRA",20},
        {"STA",25},{"ORT",20},{"FEI",20},{"LIN",20},{"FTL",15},
        {"OTT",20},{"ERG",20},
    };
    int ntri = (int)(sizeof(tris) / sizeof(tris[0]));
    for (int i = 0; i < ntri; i++) {
        int a = tris[i].t[0]-'A', b = tris[i].t[1]-'A', c = tris[i].t[2]-'A';
        tri_score[a][b][c] = tris[i].s;
    }
}

/* Fast modular reduction for values in [-26, 51] */
static inline int m26(int x)
{
    if (x < 0)   return x + 26;
    if (x >= 26) return x - 26;
    return x;
}

/* ────────────────────────────────────────────────────────── */
/*  Plugboard helpers                                         */
/* ────────────────────────────────────────────────────────── */

static void plug_init(int *p) { for (int i = 0; i < 26; i++) p[i] = i; }
static void plug_add(int *p, int a, int b) { p[a] = b; p[b] = a; }

/* ────────────────────────────────────────────────────────── */
/*  Enigma M3 encrypt                                         */
/*  r0,r1,r2 = left,middle,right rotor indices                */
/*  p0,p1,p2 = initial positions (0–25)                       */
/*  g0,g1,g2 = ring settings (0–25)                           */
/* ────────────────────────────────────────────────────────── */

static void m3_encrypt(
    int r0, int r1, int r2,
    int p0, int p1, int p2,
    int g0, int g1, int g2,
    int ref, const int *plug,
    const char *ct, int n, char *out)
{
    int pos0 = p0, pos1 = p1, pos2 = p2;
    for (int i = 0; i < n; i++) {
        int c = ct[i] - 'A';
        c = plug[c];

        /* Step rotors (double-stepping logic) */
        if (rnotch[r1][pos1]) {
            pos0 = (pos0 + 1) % 26;
            pos1 = (pos1 + 1) % 26;
        } else if (rnotch[r2][pos2]) {
            pos1 = (pos1 + 1) % 26;
        }
        pos2 = (pos2 + 1) % 26;

        /* Forward: right → middle → left */
        int o2 = pos2 - g2;
        c = m26(rfwd[r2][m26(c + o2)] - o2);
        int o1 = pos1 - g1;
        c = m26(rfwd[r1][m26(c + o1)] - o1);
        int o0 = pos0 - g0;
        c = m26(rfwd[r0][m26(c + o0)] - o0);

        /* Reflector */
        c = refw[ref][c];

        /* Backward: left → middle → right */
        c = m26(rbwd[r0][m26(c + o0)] - o0);
        c = m26(rbwd[r1][m26(c + o1)] - o1);
        c = m26(rbwd[r2][m26(c + o2)] - o2);

        c = plug[c];
        out[i] = c + 'A';
    }
    out[n] = '\0';
}

/* ────────────────────────────────────────────────────────── */
/*  Enigma M4 encrypt                                         */
/*  thin      = thin rotor index (beta/gamma)                 */
/*  tp, tg    = thin rotor position / ring (never steps)      */
/* ────────────────────────────────────────────────────────── */

static void m4_encrypt(
    int thin, int r0, int r1, int r2,
    int tp, int p0, int p1, int p2,
    int tg, int g0, int g1, int g2,
    int ref, const int *plug,
    const char *ct, int n, char *out)
{
    int pos0 = p0, pos1 = p1, pos2 = p2;
    int to = tp - tg;             /* thin offset (constant) */
    for (int i = 0; i < n; i++) {
        int c = ct[i] - 'A';
        c = plug[c];

        /* Step (same as M3; thin rotor never steps) */
        if (rnotch[r1][pos1]) {
            pos0 = (pos0 + 1) % 26;
            pos1 = (pos1 + 1) % 26;
        } else if (rnotch[r2][pos2]) {
            pos1 = (pos1 + 1) % 26;
        }
        pos2 = (pos2 + 1) % 26;

        /* Forward: right → middle → left → thin */
        int o2 = pos2 - g2;
        c = m26(rfwd[r2][m26(c + o2)] - o2);
        int o1 = pos1 - g1;
        c = m26(rfwd[r1][m26(c + o1)] - o1);
        int o0 = pos0 - g0;
        c = m26(rfwd[r0][m26(c + o0)] - o0);
        c = m26(rfwd[thin][m26(c + to)] - to);

        /* Reflector (thin) */
        c = refw[ref][c];

        /* Backward: thin → left → middle → right */
        c = m26(rbwd[thin][m26(c + to)] - to);
        c = m26(rbwd[r0][m26(c + o0)] - o0);
        c = m26(rbwd[r1][m26(c + o1)] - o1);
        c = m26(rbwd[r2][m26(c + o2)] - o2);

        c = plug[c];
        out[i] = c + 'A';
    }
    out[n] = '\0';
}

/* ────────────────────────────────────────────────────────── */
/*  Fitness functions                                         */
/* ────────────────────────────────────────────────────────── */

/* Index of Coincidence numerator (int):  Σ fᵢ(fᵢ−1) */
static int ic_num(const char *t, int n)
{
    int f[26] = {0};
    for (int i = 0; i < n; i++) f[t[i]-'A']++;
    int s = 0;
    for (int i = 0; i < 26; i++) s += f[i] * (f[i]-1);
    return s;
}

static double ic_dbl(const char *t, int n)
{
    if (n < 2) return 0.0;
    return (double)ic_num(t, n) / ((double)n * (n-1));
}

/* German trigram + common-word score (fallback when no dictionary) */
static int german_score(const char *t, int n)
{
    int s = 0;
    for (int i = 0; i < n - 2; i++)
        s += tri_score[t[i]-'A'][t[i+1]-'A'][t[i+2]-'A'];

    /* Common word bonuses */
    static const struct { const char *w; int len; } words[] = {
        {"EIN",3},{"IST",3},{"UND",3},{"DER",3},{"DIE",3},
        {"SICH",4},{"AUCH",4},{"NOCH",4},{"WIRD",4},{"NICHT",5},
        {"ANGRIFF",7},{"STANDORT",8},{"FEIND",5},{"GEGNER",6},
        {"WETTER",6},{"ORT",3},{"ZEIT",4},
    };
    int nw = (int)(sizeof(words)/sizeof(words[0]));
    for (int w = 0; w < nw; w++)
        for (int i = 0; i <= n - words[w].len; i++)
            if (strncmp(&t[i], words[w].w, words[w].len) == 0)
                s += 25;
    return s;
}

/* ────────────────────────────────────────────────────────── */
/*  Dictionary-based German word score                          */
/*  Scans decrypted text for sequences of consecutive letters   */
/*  and checks each against the loaded dictionary hash set.     */
/*  Longer words score higher (weight = len * len).             */
/*  This is a much stronger fitness function than trigrams,     */
/*  especially for short messages.                              */
/* ────────────────────────────────────────────────────────── */

static int german_word_score(const char *t, int n)
{
    if (!dict_loaded || dict_count == 0)
        return german_score(t, n);  /* fallback to trigram scoring */

    int score = 0;
    int i = 0;

    while (i < n) {
        /* Skip non-letter characters (spaces, punctuation, etc.) */
        if (t[i] < 'A' || t[i] > 'Z') {
            i++;
            continue;
        }

        /* German Enigma used X between words (e.g. ANGRIFFXVONXOSTEN).
         * Treat X as a word delimiter so each segment is checked
         * against the dictionary independently. */
        if (t[i] == 'X') {
            i++;
            continue;
        }

        /* Find the end of this letter sequence (stop at X delimiter) */
        int start = i;
        while (i < n && t[i] >= 'A' && t[i] <= 'Z' && t[i] != 'X')
            i++;
        int seglen = i - start;

        /* Try all substrings of 3+ chars within this letter sequence.
         * We try longest first for greedy matching, then shorter ones
         * that don't overlap with found words.
         *
         * Strategy: scan for words left-to-right, greedily taking the
         * longest match at each position. This avoids counting
         * sub-words of a found word (e.g. DER inside ANGER).
         */
        int pos = 0;
        while (pos < seglen) {
            int found = 0;
            /* Try longest possible word first (up to DICT_MAX_WORD-1) */
            int maxlen = seglen - pos;
            if (maxlen >= DICT_MAX_WORD) maxlen = DICT_MAX_WORD - 1;

            for (int wlen = maxlen; wlen >= 3; wlen--) {
                if (dict_contains(&t[start + pos], wlen)) {
                    /* Weight by word length squared — longer words are
                     * exponentially more significant */
                    score += wlen * wlen;
                    pos += wlen;
                    found = 1;
                    break;
                }
            }
            if (!found)
                pos++;
        }
    }

    return score;
}

/* Unified scoring function: combines dictionary scoring with trigram
 * scoring.  Dictionary gives strong signal for exact word matches;
 * trigrams give gradient signal for partial/near-matches, which is
 * essential for plugboard hill climbing (one wrong letter shouldn't
 * zero out the entire fitness). */
static int german_fitness(const char *t, int n)
{
    if (dict_loaded && dict_count > 0)
        return german_word_score(t, n) + german_score(t, n);
    return german_score(t, n);
}

/* ────────────────────────────────────────────────────────── */
/*  Fast IC for brute-force hot loop                          */
/*  Encrypts + counts frequencies in one pass, returns IC num */
/* ────────────────────────────────────────────────────────── */

static inline int fast_ic_m3(
    int r0, int r1, int r2,
    int p0, int p1, int p2,
    int g0, int g1, int g2,
    int ref, const int *plug,
    const char *ct, int n)
{
    int pos0 = p0, pos1 = p1, pos2 = p2;
    int f[26] = {0};
    for (int i = 0; i < n; i++) {
        int c = ct[i] - 'A';
        c = plug[c];

        if (rnotch[r1][pos1]) {
            pos0 = (pos0 + 1) % 26;
            pos1 = (pos1 + 1) % 26;
        } else if (rnotch[r2][pos2]) {
            pos1 = (pos1 + 1) % 26;
        }
        pos2 = (pos2 + 1) % 26;

        int o2 = pos2 - g2;
        c = m26(rfwd[r2][m26(c + o2)] - o2);
        int o1 = pos1 - g1;
        c = m26(rfwd[r1][m26(c + o1)] - o1);
        int o0 = pos0 - g0;
        c = m26(rfwd[r0][m26(c + o0)] - o0);

        c = refw[ref][c];

        c = m26(rbwd[r0][m26(c + o0)] - o0);
        c = m26(rbwd[r1][m26(c + o1)] - o1);
        c = m26(rbwd[r2][m26(c + o2)] - o2);

        c = plug[c];
        f[c]++;
    }
    int ic = 0;
    for (int i = 0; i < 26; i++) ic += f[i] * (f[i]-1);
    return ic;
}

/* Fast IC for M4 (includes thin rotor) */
static inline int fast_ic_m4(
    int thin, int r0, int r1, int r2,
    int tp, int p0, int p1, int p2,
    int tg, int g0, int g1, int g2,
    int ref, const int *plug,
    const char *ct, int n)
{
    int pos0 = p0, pos1 = p1, pos2 = p2;
    int to = tp - tg;
    int f[26] = {0};
    for (int i = 0; i < n; i++) {
        int c = ct[i] - 'A';
        c = plug[c];

        if (rnotch[r1][pos1]) {
            pos0 = (pos0 + 1) % 26;
            pos1 = (pos1 + 1) % 26;
        } else if (rnotch[r2][pos2]) {
            pos1 = (pos1 + 1) % 26;
        }
        pos2 = (pos2 + 1) % 26;

        int o2 = pos2 - g2;
        c = m26(rfwd[r2][m26(c + o2)] - o2);
        int o1 = pos1 - g1;
        c = m26(rfwd[r1][m26(c + o1)] - o1);
        int o0 = pos0 - g0;
        c = m26(rfwd[r0][m26(c + o0)] - o0);
        c = m26(rfwd[thin][m26(c + to)] - to);

        c = refw[ref][c];

        c = m26(rbwd[thin][m26(c + to)] - to);
        c = m26(rbwd[r0][m26(c + o0)] - o0);
        c = m26(rbwd[r1][m26(c + o1)] - o1);
        c = m26(rbwd[r2][m26(c + o2)] - o2);

        c = plug[c];
        f[c]++;
    }
    int ic = 0;
    for (int i = 0; i < 26; i++) ic += f[i] * (f[i]-1);
    return ic;
}

/* ────────────────────────────────────────────────────────── */
/*  Hill climb on plugboard                                   */
/*  Phase A: greedy add pairs that improve score              */
/*  Phase B: try swapping each used letter for a better one   */
/*  Phase C: try removing pairs that decrease score           */
/* ────────────────────────────────────────────────────────── */

static int hill_climb_m3(
    int r0, int r1, int r2,
    int p0, int p1, int p2,
    int g0, int g1, int g2,
    int ref,
    const char *ct, int n,
    int *best_plug, char *best_out)
{
    plug_init(best_plug);
    m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref, best_plug, ct, n, best_out);
    int best_gs = german_fitness(best_out, n);

    int used[26] = {0};

    /* Phase A: greedy add — use IC as primary, German as secondary */
    /* IC weight must be high enough that false pairs don't sneak in */
    double best_fit = ic_num(best_out, n) * 100.0 + best_gs;
    for (int iter = 0; iter < 13; iter++) {
        int best_a = -1, best_b = -1;
        double best_new = best_fit;

        for (int a = 0; a < 26; a++) {
            if (used[a]) continue;
            for (int b = a + 1; b < 26; b++) {
                if (used[b]) continue;
                best_plug[a] = b;
                best_plug[b] = a;

                char tmp[512];
                m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref,
                           best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                /* IC_num * 100 + german_score — IC dominates */
                double fit = ic_num(tmp, n) * 100.0 + gs;

                if (fit > best_new) {
                    best_new = fit;
                    best_a = a;
                    best_b = b;
                }
                best_plug[a] = a;
                best_plug[b] = b;
            }
        }

        if (best_a < 0) break;
        best_plug[best_a] = best_b;
        best_plug[best_b] = best_a;
        used[best_a] = 1;
        used[best_b] = 1;
        best_fit = best_new;
    }

    /* Phase B: try replacing each paired letter with a free letter */
    for (int round = 0; round < 3; round++) {
        int improved = 0;
        for (int a = 0; a < 26; a++) {
            if (!used[a]) continue;
            int b = best_plug[a];
            /* Try replacing a with a free letter */
            for (int c = 0; c < 26; c++) {
                if (used[c] || c == b) continue;
                /* Unplug a-b, plug c-b */
                best_plug[a] = a;
                best_plug[b] = b;
                best_plug[c] = b;
                best_plug[b] = c;

                char tmp[512];
                m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref,
                           best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;

                if (fit > best_fit) {
                    best_fit = fit;
                    used[a] = 0;
                    used[c] = 1;
                    improved = 1;
                } else {
                    /* Revert */
                    best_plug[c] = c;
                    best_plug[b] = a;
                    best_plug[a] = b;
                }
            }
            /* Try replacing b with a free letter */
            for (int c = 0; c < 26; c++) {
                if (used[c] || c == a) continue;
                best_plug[b] = b;
                best_plug[a] = a;
                best_plug[c] = a;
                best_plug[a] = c;

                char tmp[512];
                m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref,
                           best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;

                if (fit > best_fit) {
                    best_fit = fit;
                    used[b] = 0;
                    used[c] = 1;
                    improved = 1;
                } else {
                    best_plug[c] = c;
                    best_plug[a] = b;
                    best_plug[b] = a;
                }
            }
        }
        if (!improved) break;
    }

    /* Phase C: try removing each pair to see if score improves */
    for (int a = 0; a < 26; a++) {
        if (!used[a]) continue;
        int b = best_plug[a];
        best_plug[a] = a;
        best_plug[b] = b;

        char tmp[512];
        m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref,
                   best_plug, ct, n, tmp);
        int gs = german_fitness(tmp, n);
        double fit = ic_num(tmp, n) * 100.0 + gs;

        if (fit > best_fit) {
            best_fit = fit;
            used[a] = 0;
            used[b] = 0;
        } else {
            best_plug[a] = b;
            best_plug[b] = a;
        }
    }

    m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref, best_plug, ct, n, best_out);
    return german_fitness(best_out, n);
}

/* Hill climb for M4 (same algorithm, uses m4_encrypt) */
static int hill_climb_m4(
    int thin, int r0, int r1, int r2,
    int tp, int p0, int p1, int p2,
    int tg, int g0, int g1, int g2,
    int ref,
    const char *ct, int n,
    int *best_plug, char *best_out)
{
    plug_init(best_plug);
    m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref, best_plug, ct, n, best_out);
    int best_gs = german_fitness(best_out, n);

    int used[26] = {0};
    double best_fit = ic_num(best_out, n) * 100.0 + best_gs;

    for (int iter = 0; iter < 13; iter++) {
        int best_a = -1, best_b = -1;
        double best_new = best_fit;

        for (int a = 0; a < 26; a++) {
            if (used[a]) continue;
            for (int b = a + 1; b < 26; b++) {
                if (used[b]) continue;
                best_plug[a] = b;
                best_plug[b] = a;

                char tmp[512];
                m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref,
                           best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;

                if (fit > best_new) {
                    best_new = fit;
                    best_a = a;
                    best_b = b;
                }
                best_plug[a] = a;
                best_plug[b] = b;
            }
        }

        if (best_a < 0) break;
        best_plug[best_a] = best_b;
        best_plug[best_b] = best_a;
        used[best_a] = 1;
        used[best_b] = 1;
        best_fit = best_new;
    }

    /* Phase B: try replacing each paired letter with a free letter */
    for (int round = 0; round < 3; round++) {
        int improved = 0;
        for (int a = 0; a < 26; a++) {
            if (!used[a]) continue;
            int b = best_plug[a];
            for (int c = 0; c < 26; c++) {
                if (used[c] || c == b) continue;
                best_plug[a] = a;
                best_plug[b] = b;
                best_plug[c] = b;
                best_plug[b] = c;

                char tmp[512];
                m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref,
                           best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;

                if (fit > best_fit) {
                    best_fit = fit;
                    used[a] = 0; used[c] = 1;
                    improved = 1;
                } else {
                    best_plug[c] = c;
                    best_plug[b] = a;
                    best_plug[a] = b;
                }
            }
            for (int c = 0; c < 26; c++) {
                if (used[c] || c == a) continue;
                best_plug[b] = b;
                best_plug[a] = a;
                best_plug[c] = a;
                best_plug[a] = c;

                char tmp[512];
                m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref,
                           best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;

                if (fit > best_fit) {
                    best_fit = fit;
                    used[b] = 0; used[c] = 1;
                    improved = 1;
                } else {
                    best_plug[c] = c;
                    best_plug[a] = b;
                    best_plug[b] = a;
                }
            }
        }
        if (!improved) break;
    }

    /* Phase C: try removing each pair */
    for (int a = 0; a < 26; a++) {
        if (!used[a]) continue;
        int b = best_plug[a];
        best_plug[a] = a;
        best_plug[b] = b;

        char tmp[512];
        m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref,
                   best_plug, ct, n, tmp);
        int gs = german_fitness(tmp, n);
        double fit = ic_num(tmp, n) * 100.0 + gs;

        if (fit > best_fit) {
            best_fit = fit;
            used[a] = 0; used[b] = 0;
        } else {
            best_plug[a] = b;
            best_plug[b] = a;
        }
    }

    m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref, best_plug, ct, n, best_out);
    return german_fitness(best_out, n);
}

/* ────────────────────────────────────────────────────────── */
/*  Crack result structure                                     */
/* ────────────────────────────────────────────────────────── */

typedef struct {
    int r0, r1, r2;        /* rotor indices (left, middle, right) */
    int thin;              /* thin rotor index (M4 only) */
    int ref;               /* reflector index */
    int p0, p1, p2;        /* positions */
    int tp;                /* thin rotor position (M4 only) */
    int g0, g1, g2;        /* ring settings */
    int tg;                /* thin rotor ring (M4 only) */
    int plug[26];          /* plugboard */
    char text[512];        /* decrypted plaintext */
    int german_score;      /* German fitness score */
    double elapsed;        /* total elapsed time in seconds */
    long long configs;     /* total configurations tried */
    int is_m4;             /* 1 = M4, 0 = M3 */
} CrackResult;

/* ────────────────────────────────────────────────────────── */
/*  Brute-force M3                                            */
/*  Phase 1: all rotor perms × reflectors × positions         */
/*           (rings = AAA) → top candidates by IC             */
/*  Phase 2: ring search on top candidates                    */
/*  Phase 3: hill climb plugboard on best candidates          */
/* ────────────────────────────────────────────────────────── */

#define MAX_CAND 500

typedef struct {
    int ic;
    int r0, r1, r2;
    int ref;
    int p0, p1, p2;
    int g0, g1, g2;   /* best ring settings found in Phase 2 */
    int tg;           /* thin rotor ring (M4 only) */
    int thin;         /* thin rotor index (M4 only) */
    int tp;           /* thin rotor position (M4 only) */
} Cand;

static int cand_cmp(const void *a, const void *b)
{
    return ((const Cand *)b)->ic - ((const Cand *)a)->ic;
}

static CrackResult brute_force_m3(const char *ct, int n, int json_mode)
{
    CrackResult result;
    memset(&result, 0, sizeof(result));
    result.is_m4 = 0;

    /* Rotors to search: I–VIII (8 rotors → 336 permutations) */
    int sr[8] = {R_I, R_II, R_III, R_IV, R_V, R_VI, R_VII, R_VIII};
    int sref[2] = {REF_B, REF_C};
    int idplug[26]; plug_init(idplug);

    /* IC threshold — lowered for better short-message coverage */
    int thresh = (int)(0.035 * (double)n * (n - 1));

    Cand cand[MAX_CAND];
    int ncand = 0;
    int min_ic = 0;

    long long total = 336LL * 2 * 26*26*26;
    if (!json_mode)
        printf("Phase 1: %lld configs (336 rotor perms × 2 reflectors × 26³ positions, rings=AAA)\n", total);
    fprintf(stderr, "PROGRESS:phase1:0:%lld\n", total);
    fflush(stderr);

    double t0 = now_sec();
    long long cnt = 0;

    #pragma omp parallel for collapse(2) schedule(dynamic) reduction(+:cnt) shared(cand, ncand, min_ic)
    for (int ai = 0; ai < 8; ai++)
    for (int aj = 0; aj < 8; aj++) {
        if (aj == ai) continue;
        for (int ak = 0; ak < 8; ak++) {
            if (ak == ai || ak == aj) continue;
            int r0 = sr[ai], r1 = sr[aj], r2 = sr[ak];

            for (int rf = 0; rf < 2; rf++)
            for (int p0 = 0; p0 < 26; p0++)
            for (int p1 = 0; p1 < 26; p1++)
            for (int p2 = 0; p2 < 26; p2++) {
                cnt++;
                int ic = fast_ic_m3(r0,r1,r2, p0,p1,p2, 0,0,0, sref[rf], idplug, ct, n);

                if (ic > thresh) {
                    #pragma omp critical(cand_m3)
                    {
                    if (ncand < MAX_CAND) {
                        cand[ncand].ic = ic;
                        cand[ncand].r0 = r0; cand[ncand].r1 = r1; cand[ncand].r2 = r2;
                        cand[ncand].ref = sref[rf];
                        cand[ncand].p0 = p0; cand[ncand].p1 = p1; cand[ncand].p2 = p2;
                        cand[ncand].g0 = 0; cand[ncand].g1 = 0; cand[ncand].g2 = 0;
                        ncand++;
                        if (ic < min_ic || ncand == 1) min_ic = ic;
                        /* recompute min if array just filled */
                        if (ncand == MAX_CAND) {
                            min_ic = INT_MAX;
                            for (int k = 0; k < ncand; k++)
                                if (cand[k].ic < min_ic) min_ic = cand[k].ic;
                        }
                    } else if (ic > min_ic) {
                        /* replace worst */
                        int mi = 0;
                        for (int k = 1; k < ncand; k++)
                            if (cand[k].ic < cand[mi].ic) mi = k;
                        cand[mi] = cand[ncand-1]; /* swap out worst */
                        ncand--;
                        /* insert new */
                        cand[ncand].ic = ic;
                        cand[ncand].r0 = r0; cand[ncand].r1 = r1; cand[ncand].r2 = r2;
                        cand[ncand].ref = sref[rf];
                        cand[ncand].p0 = p0; cand[ncand].p1 = p1; cand[ncand].p2 = p2;
                        cand[ncand].g0 = 0; cand[ncand].g1 = 0; cand[ncand].g2 = 0;
                        ncand++;
                        /* recompute min */
                        min_ic = INT_MAX;
                        for (int k = 0; k < ncand; k++)
                            if (cand[k].ic < min_ic) min_ic = cand[k].ic;
                    }
                    }
                }
            }
        }
    }

    double t1 = now_sec();
    fprintf(stderr, "PROGRESS:phase1:done:%lld\n", total);
    fflush(stderr);

    if (!json_mode) {
        printf("  Done: %lld configs in %.2fs (%.0f/s)\n", cnt, t1-t0, cnt/(t1-t0));
        printf("  Candidates above IC threshold: %d\n\n", ncand);
    }

    if (ncand == 0) {
        if (!json_mode)
            printf("  *** No candidates found — try lowering threshold ***\n");
        result.elapsed = t1 - t0;
        result.configs = cnt;
        result.german_score = -1;
        return result;
    }

    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    /* Phase 2: ring search on ALL candidates */
    /* Search all 26^3 ring settings for every candidate so that even
       settings with mediocre IC at rings=AAA get a full ring sweep. */
    int top_rings = ncand;
    if (!json_mode)
        printf("Phase 2: Ring search on all %d candidates (26³ = 17,576 rings each)...\n", top_rings);
    fprintf(stderr, "PROGRESS:phase2:0:%d\n", top_rings);
    fflush(stderr);

    for (int c = 0; c < top_rings; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        /* Use combined IC + German fitness for ring search.
           IC alone rarely distinguishes ring settings (it measures
           frequency distribution, which barely changes with rings).
           German word score responds to the actual decryption quality. */
        char tmp[512];
        m3_encrypt(r0,r1,r2, p0,p1,p2, 0,0,0, rf, idplug, ct, n, tmp);
        int best_fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
        int bg0 = 0, bg1 = 0, bg2 = 0;

        for (int g0 = 0; g0 < 26; g0++)
        for (int g1 = 0; g1 < 26; g1++)
        for (int g2 = 0; g2 < 26; g2++) {
            m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, rf, idplug, ct, n, tmp);
            int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
            if (fit > best_fit) {
                best_fit = fit;
                bg0 = g0; bg1 = g1; bg2 = g2;
            }
        }
        /* Update candidate IC to the IC at best rings (for re-sorting) */
        m3_encrypt(r0,r1,r2, p0,p1,p2, bg0,bg1,bg2, rf, idplug, ct, n, tmp);
        cand[c].ic = ic_num(tmp, n);
        cand[c].g0 = bg0;
        cand[c].g1 = bg1;
        cand[c].g2 = bg2;
        fprintf(stderr, "PROGRESS:phase2:%d:%d\n", c+1, top_rings);
        fflush(stderr);
    }

    /* Re-sort after ring search */
    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    double t2 = now_sec();
    if (!json_mode)
        printf("  Done in %.2fs\n\n", t2-t1);

    /* Phase 3: hill climb plugboard on top 10 */
    int top_hc = ncand < 10 ? ncand : 10;
    if (!json_mode)
        printf("Phase 3: Hill climb plugboard on top %d candidates\n\n", top_hc);
    fprintf(stderr, "PROGRESS:phase3:0:%d\n", top_hc);
    fflush(stderr);

    int best_gs = -1;
    int best_plug[26];
    char best_text[512];
    int bR0=0,bR1=0,bR2=0,bRef=0,bP0=0,bP1=0,bP2=0,bG0=0,bG1=0,bG2=0;

    for (int c = 0; c < top_hc; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        /* Use the best ring settings found in Phase 2 */
        int bg0 = cand[c].g0, bg1 = cand[c].g1, bg2 = cand[c].g2;

        int plug[26];
        char out[512];

        /* Hill climb with the best ring settings from Phase 2 */
        int gs = hill_climb_m3(r0,r1,r2, p0,p1,p2, bg0,bg1,bg2, rf, ct, n, plug, out);

        memcpy(best_plug, plug, sizeof(plug));
        strcpy(best_text, out);

        if (!json_mode) {
            printf("  #%d  Rotors %s,%s,%s  Ref %s  Pos %c%c%c  Rings %c%c%c\n",
                   c+1,
                   ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2],
                   REFLECTOR_NAME[rf],
                   p0+'A', p1+'A', p2+'A',
                   bg0+'A', bg1+'A', bg2+'A');
            printf("       IC=%.4f  German=%d\n", ic_dbl(out, n), gs);
            printf("       Plug: ");
            for (int i = 0; i < 26; i++)
                if (best_plug[i] > i) printf("%c%c ", i+'A', best_plug[i]+'A');
            printf("\n       Text: %s\n\n", best_text);
        }

        fprintf(stderr, "PROGRESS:phase3:%d:%d\n", c+1, top_hc);
        fflush(stderr);

        if (gs > best_gs) {
            best_gs = gs;
            bR0=r0; bR1=r1; bR2=r2; bRef=rf;
            bP0=p0; bP1=p1; bP2=p2;
            bG0=bg0; bG1=bg1; bG2=bg2;
        }
    }

    double t3 = now_sec();

    /* Fill result struct */
    result.r0 = bR0; result.r1 = bR1; result.r2 = bR2;
    result.ref = bRef;
    result.p0 = bP0; result.p1 = bP1; result.p2 = bP2;
    result.g0 = bG0; result.g1 = bG1; result.g2 = bG2;
    memcpy(result.plug, best_plug, sizeof(best_plug));
    strncpy(result.text, best_text, sizeof(result.text)-1);
    result.text[sizeof(result.text)-1] = '\0';
    result.german_score = best_gs;
    result.elapsed = t3 - t0;
    result.configs = cnt;

    if (!json_mode) {
        printf("════════════════════════════════════════\n");
        printf("BEST RESULT\n");
        printf("════════════════════════════════════════\n");
        printf("Rotors:      %s, %s, %s (L,M,R)\n",
               ROTOR_NAME[bR0], ROTOR_NAME[bR1], ROTOR_NAME[bR2]);
        printf("Reflector:   %s\n", REFLECTOR_NAME[bRef]);
        printf("Positions:   %c%c%c\n", bP0+'A', bP1+'A', bP2+'A');
        printf("Rings:       %c%c%c\n", bG0+'A', bG1+'A', bG2+'A');
        printf("Plugboard:   ");
        for (int i = 0; i < 26; i++)
            if (best_plug[i] > i) printf("%c%c ", i+'A', best_plug[i]+'A');
        printf("\nPlaintext:   %s\n", best_text);
        printf("German score: %d\n", best_gs);
        printf("Total time:  %.2fs\n", t3 - t0);
    }

    return result;
}

/* ────────────────────────────────────────────────────────── */
/*  Brute-force M4                                            */
/*  Searches: thin rotor (beta/gamma) × thin position ×       */
/*            M3-style search on remaining 3 rotors           */
/*  Reflectors: B_thin, C_thin                                */
/* ────────────────────────────────────────────────────────── */

static CrackResult brute_force_m4(const char *ct, int n, int json_mode)
{
    CrackResult result;
    memset(&result, 0, sizeof(result));
    result.is_m4 = 1;

    int sr[8] = {R_I, R_II, R_III, R_IV, R_V, R_VI, R_VII, R_VIII};
    int sref[2] = {REF_B_THIN, REF_C_THIN};
    int thin_rotors[2] = {R_BETA, R_GAMMA};
    int idplug[26]; plug_init(idplug);

    int thresh = (int)(0.035 * (double)n * (n - 1));

    /* Total: 2 thin × 26 thin_pos × 336 rotor_perms × 2 ref × 26³ positions */
    long long total = 2LL * 26 * 336 * 2 * 26*26*26;
    if (!json_mode) {
        printf("M4 Brute-force: %lld configs (2 thin × 26 thin_pos × 336 rotor perms × 2 ref × 26³ pos)\n", total);
        printf("Phase 1: Searching rotor permutations and positions (rings=AAAA)...\n");
    }
    fprintf(stderr, "PROGRESS:phase1:0:%lld\n", total);
    fflush(stderr);

    double t0 = now_sec();
    long long cnt = 0;

    Cand cand[MAX_CAND];
    int ncand = 0;
    int min_ic = 0;

    #pragma omp parallel for collapse(2) schedule(dynamic) reduction(+:cnt) shared(cand, ncand, min_ic)
    for (int thi = 0; thi < 2; thi++)
    for (int tp = 0; tp < 26; tp++) {
        for (int ai = 0; ai < 8; ai++)
        for (int aj = 0; aj < 8; aj++) {
            if (aj == ai) continue;
            for (int ak = 0; ak < 8; ak++) {
                if (ak == ai || ak == aj) continue;
                int r0 = sr[ai], r1 = sr[aj], r2 = sr[ak];

                for (int rf = 0; rf < 2; rf++)
                for (int p0 = 0; p0 < 26; p0++)
                for (int p1 = 0; p1 < 26; p1++)
                for (int p2 = 0; p2 < 26; p2++) {
                    cnt++;
                    int ic = fast_ic_m4(thin_rotors[thi], r0,r1,r2,
                                        tp, p0,p1,p2,
                                        0, 0,0,0,
                                        sref[rf], idplug, ct, n);

                    if (ic > thresh) {
                        #pragma omp critical(cand_m4)
                        {
                        if (ncand < MAX_CAND) {
                            cand[ncand].ic = ic;
                            cand[ncand].r0 = r0; cand[ncand].r1 = r1; cand[ncand].r2 = r2;
                            cand[ncand].ref = sref[rf];
                            cand[ncand].p0 = p0; cand[ncand].p1 = p1; cand[ncand].p2 = p2;
                            cand[ncand].g0 = 0; cand[ncand].g1 = 0; cand[ncand].g2 = 0;
                            cand[ncand].thin = thin_rotors[thi];
                            cand[ncand].tp = tp;
                            ncand++;
                            if (ic < min_ic || ncand == 1) min_ic = ic;
                            if (ncand == MAX_CAND) {
                                min_ic = INT_MAX;
                                for (int k = 0; k < ncand; k++)
                                    if (cand[k].ic < min_ic) min_ic = cand[k].ic;
                            }
                        } else if (ic > min_ic) {
                            int mi = 0;
                            for (int k = 1; k < ncand; k++)
                                if (cand[k].ic < cand[mi].ic) mi = k;
                            cand[mi] = cand[ncand-1];
                            ncand--;
                            cand[ncand].ic = ic;
                            cand[ncand].r0 = r0; cand[ncand].r1 = r1; cand[ncand].r2 = r2;
                            cand[ncand].ref = sref[rf];
                            cand[ncand].p0 = p0; cand[ncand].p1 = p1; cand[ncand].p2 = p2;
                            cand[ncand].g0 = 0; cand[ncand].g1 = 0; cand[ncand].g2 = 0;
                            cand[ncand].thin = thin_rotors[thi];
                            cand[ncand].tp = tp;
                            ncand++;
                            min_ic = INT_MAX;
                            for (int k = 0; k < ncand; k++)
                                if (cand[k].ic < min_ic) min_ic = cand[k].ic;
                        }
                        }
                    }
                }
            }
        }
    }

    double t1 = now_sec();
    fprintf(stderr, "PROGRESS:phase1:done:%lld\n", total);
    fflush(stderr);

    if (!json_mode) {
        printf("  Done: %lld configs in %.2fs (%.0f/s)\n", cnt, t1-t0, cnt/(t1-t0));
        printf("  Candidates above IC threshold: %d\n\n", ncand);
    }

    if (ncand == 0) {
        if (!json_mode)
            printf("  *** No candidates found — try lowering threshold ***\n");
        result.elapsed = t1 - t0;
        result.configs = cnt;
        result.german_score = -1;
        return result;
    }

    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    /* Phase 2: ring search on ALL candidates */
    /* Search all 26^4 ring settings for every candidate (including thin ring) */
    int top_rings = ncand;
    if (!json_mode)
        printf("Phase 2: Ring search on all %d candidates (26^4 = 456,976 rings each)...\n", top_rings);
    fprintf(stderr, "PROGRESS:phase2:0:%d\n", top_rings);
    fflush(stderr);

    for (int c = 0; c < top_rings; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        int thin = cand[c].thin;
        int tp = cand[c].tp;
        /* Use combined IC + German fitness for ring search (same as M3) */
        char tmp[512];
        m4_encrypt(thin, r0,r1,r2, tp,p0,p1,p2, 0,0,0,0, rf, idplug, ct, n, tmp);
        int best_fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
        int bg0 = 0, bg1 = 0, bg2 = 0, btg = 0;

        /* Search all 26^4 ring settings (including thin ring tg) */
        for (int tg = 0; tg < 26; tg++)
        for (int g0 = 0; g0 < 26; g0++)
        for (int g1 = 0; g1 < 26; g1++)
        for (int g2 = 0; g2 < 26; g2++) {
            m4_encrypt(thin, r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, rf, idplug, ct, n, tmp);
            int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
            if (fit > best_fit) {
                best_fit = fit;
                bg0 = g0; bg1 = g1; bg2 = g2; btg = tg;
            }
        }

        /* Update candidate IC to the IC at best rings (for re-sorting) */
        m4_encrypt(thin, r0,r1,r2, tp,p0,p1,p2, btg,bg0,bg1,bg2, rf, idplug, ct, n, tmp);
        cand[c].ic = ic_num(tmp, n);
        cand[c].g0 = bg0;
        cand[c].g1 = bg1;
        cand[c].g2 = bg2;
        cand[c].tg = btg;

        fprintf(stderr, "PROGRESS:phase2:%d:%d\n", c+1, top_rings);
        fflush(stderr);
    }

    /* Re-sort after ring search */
    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    double t2 = now_sec();
    if (!json_mode)
        printf("  Done in %.2fs\n\n", t2-t1);

    /* Phase 3: hill climb plugboard on top 10 */
    int top_hc = ncand < 10 ? ncand : 10;
    if (!json_mode)
        printf("Phase 3: Hill climb plugboard on top %d candidates\n\n", top_hc);
    fprintf(stderr, "PROGRESS:phase3:0:%d\n", top_hc);
    fflush(stderr);

    int best_gs = -1;
    int best_plug[26];
    char best_text[512];
    int bThin=R_BETA, bR0=0,bR1=0,bR2=0,bRef=0,bP0=0,bP1=0,bP2=0,bTp=0;
    int bG0=0,bG1=0,bG2=0,bTg=0;

    for (int c = 0; c < top_hc; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        int thin = cand[c].thin;
        int tp = cand[c].tp;
        /* Use the best ring settings found in Phase 2 */
        int bg0 = cand[c].g0, bg1 = cand[c].g1, bg2 = cand[c].g2;
        int btg = cand[c].tg;

        int plug[26];
        char out[512];

        /* Hill climb with the best ring settings from Phase 2 */
        int gs = hill_climb_m4(thin, r0,r1,r2, tp,p0,p1,p2, btg,bg0,bg1,bg2, rf, ct, n, plug, out);

        memcpy(best_plug, plug, sizeof(plug));
        strcpy(best_text, out);

        if (!json_mode) {
            printf("  #%d  Thin %s  Rotors %s,%s,%s  Ref %s  ThinPos %c  Pos %c%c%c  Rings %c%c%c%c\n",
                   c+1,
                   ROTOR_NAME[thin],
                   ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2],
                   REFLECTOR_NAME[rf],
                   tp+'A',
                   p0+'A', p1+'A', p2+'A',
                   btg+'A', bg0+'A', bg1+'A', bg2+'A');
            printf("       IC=%.4f  German=%d\n", ic_dbl(out, n), gs);
            printf("       Plug: ");
            for (int i = 0; i < 26; i++)
                if (best_plug[i] > i) printf("%c%c ", i+'A', best_plug[i]+'A');
            printf("\n       Text: %s\n\n", best_text);
        }

        fprintf(stderr, "PROGRESS:phase3:%d:%d\n", c+1, top_hc);
        fflush(stderr);

        if (gs > best_gs) {
            best_gs = gs;
            bThin = thin;
            bR0=r0; bR1=r1; bR2=r2; bRef=rf;
            bTp=tp; bP0=p0; bP1=p1; bP2=p2;
            bG0=bg0; bG1=bg1; bG2=bg2; bTg=btg;
        }
    }

    double t3 = now_sec();

    /* Fill result struct */
    result.thin = bThin;
    result.r0 = bR0; result.r1 = bR1; result.r2 = bR2;
    result.ref = bRef;
    result.tp = bTp;
    result.p0 = bP0; result.p1 = bP1; result.p2 = bP2;
    result.g0 = bG0; result.g1 = bG1; result.g2 = bG2;
    result.tg = bTg;
    memcpy(result.plug, best_plug, sizeof(best_plug));
    strncpy(result.text, best_text, sizeof(result.text)-1);
    result.text[sizeof(result.text)-1] = '\0';
    result.german_score = best_gs;
    result.elapsed = t3 - t0;
    result.configs = cnt;

    if (!json_mode) {
        printf("════════════════════════════════════════\n");
        printf("BEST RESULT (M4)\n");
        printf("════════════════════════════════════════\n");
        printf("Thin rotor:  %s\n", ROTOR_NAME[bThin]);
        printf("Rotors:      %s, %s, %s (L,M,R)\n",
               ROTOR_NAME[bR0], ROTOR_NAME[bR1], ROTOR_NAME[bR2]);
        printf("Reflector:   %s\n", REFLECTOR_NAME[bRef]);
        printf("Thin Pos:    %c\n", bTp+'A');
        printf("Positions:   %c%c%c\n", bP0+'A', bP1+'A', bP2+'A');
        printf("Rings:       %c%c%c%c\n", bTg+'A', bG0+'A', bG1+'A', bG2+'A');
        printf("Plugboard:   ");
        for (int i = 0; i < 26; i++)
            if (best_plug[i] > i) printf("%c%c ", i+'A', best_plug[i]+'A');
        printf("\nPlaintext:   %s\n", best_text);
        printf("German score: %d\n", best_gs);
        printf("Total time:  %.2fs\n", t3 - t0);
    }

    return result;
}

/* ────────────────────────────────────────────────────────── */
/*  Indicator-based message key recovery                      */
/*                                                            */
/*  German Enigma procedures transmitted indicator groups as  */
/*  the first letters of the ciphertext.  These encode the    */
/*  message key (initial rotor positions for the actual       */
/*  message).                                                 */
/*                                                            */
/*  M3: The 3-letter message key was encrypted TWICE (6       */
/*      letters total) using the day key's Grundstellung.     */
/*      Positions 1-3 and 4-6 of the indicator should decrypt */
/*      to the SAME 3-letter key.  This doubled-indicator     */
/*      weakness was exploited by Bletchley Park.  We use it  */
/*      as a filter: if the two halves don't match, the       */
/*      settings are wrong and we skip immediately.            */
/*                                                            */
/*  M4: The indicator is more complex (K-book/bigram system). */
/*      We use the first 3 indicator letters as a position     */
/*      hint: for each candidate Grundstellung, decrypt the   */
/*      indicator to get the message key, then decrypt the    */
/*      rest of the ciphertext at that message key.           */
/* ────────────────────────────────────────────────────────── */

/* M3 indicator brute-force.
 * indicator = first 6 letters of ciphertext (doubled message key)
 * ct = ciphertext AFTER stripping the indicator
 * n = length of ct
 * ind = indicator string (6 letters)
 * ind_n = length of indicator (should be 6)
 *
 * For each rotor perm × reflector × Grundstellung position:
 *   1. Decrypt the 6 indicator letters through the Enigma at Grundstellung
 *   2. Check if positions 1-3 == positions 4-6 (doubled indicator check)
 *   3. If match: use the first 3 letters as the message key
 *   4. Decrypt the actual ciphertext at the message key
 *   5. Score with IC + German fitness
 * The doubled-indicator filter eliminates ~99.6% of wrong settings
 * immediately (probability of random match = 1/26^3 ≈ 0.006%).
 */
static CrackResult brute_force_m3_indicator(
    const char *ct, int n,
    const char *ind, int ind_n,
    int json_mode)
{
    CrackResult result;
    memset(&result, 0, sizeof(result));
    result.is_m4 = 0;

    int sr[8] = {R_I, R_II, R_III, R_IV, R_V, R_VI, R_VII, R_VIII};
    int sref[2] = {REF_B, REF_C};
    int idplug[26]; plug_init(idplug);

    /* We need at least 6 indicator letters for the doubled-key check */
    if (ind_n < 6) {
        if (!json_mode)
            printf("M3 indicator mode requires at least 6 indicator letters (got %d)\n", ind_n);
        result.german_score = -1;
        return result;
    }

    /* Only need 3 indicator letters for the doubled check, but we use 6 */
    int ind3_n = 3;   /* first half */
    char ind_first[8];
    strncpy(ind_first, ind, 3);
    ind_first[3] = '\0';

    int thresh = (int)(0.035 * (double)n * (n - 1));

    Cand cand[MAX_CAND];
    int ncand = 0;
    int min_ic = 0;

    /* Total: 336 perms × 2 reflectors × 26^3 Grundstellung positions */
    long long total = 336LL * 2 * 26 * 26 * 26;
    if (!json_mode) {
        printf("M3 Indicator mode: doubled indicator filter\n");
        printf("Indicator (6 letters): %c%c%c %c%c%c\n",
               ind[0], ind[1], ind[2], ind[3], ind[4], ind[5]);
        printf("Phase 1: %lld configs (336 perms × 2 ref × 26³ Grundstellungen, rings=AAA)\n", total);
    }
    fprintf(stderr, "PROGRESS:phase1:0:%lld\n", total);
    fflush(stderr);

    double t0 = now_sec();
    long long cnt = 0;
    long long filtered = 0;

    #pragma omp parallel for collapse(2) schedule(dynamic) reduction(+:cnt,filtered) shared(cand, ncand, min_ic)
    for (int ai = 0; ai < 8; ai++)
    for (int aj = 0; aj < 8; aj++) {
        if (aj == ai) continue;
        for (int ak = 0; ak < 8; ak++) {
            if (ak == ai || ak == aj) continue;
            int r0 = sr[ai], r1 = sr[aj], r2 = sr[ak];

            for (int rf = 0; rf < 2; rf++)
            for (int g0 = 0; g0 < 26; g0++)     /* Grundstellung positions */
            for (int g1 = 0; g1 < 26; g1++)
            for (int g2 = 0; g2 < 26; g2++) {
                cnt++;

                /* Step 1: Decrypt the 6 indicator letters at this Grundstellung (rings=AAA) */
                char ind_out[8];
                m3_encrypt(r0, r1, r2, g0, g1, g2, 0, 0, 0,
                           sref[rf], idplug, ind, 6, ind_out);

                /* Step 2: Doubled indicator check — first 3 must match second 3 */
                if (ind_out[0] != ind_out[3] ||
                    ind_out[1] != ind_out[4] ||
                    ind_out[2] != ind_out[5])
                    continue;   /* filter rejects — skip this config */

                filtered++;

                /* Step 3: The message key is the first 3 decrypted letters */
                int mk0 = ind_out[0] - 'A';
                int mk1 = ind_out[1] - 'A';
                int mk2 = ind_out[2] - 'A';

                /* Step 3b: Score decrypted indicator against common operator keys.
                 * The doubled-indicator check already gives us high confidence,
                 * but scoring against operator keys provides additional fitness
                 * signal — operators often used recognizable keys. */
                char ind_key[4];
                ind_key[0] = ind_out[0];
                ind_key[1] = ind_out[1];
                ind_key[2] = ind_out[2];
                ind_key[3] = '\0';
                int op_score = score_operator_key(ind_key, 3);

                /* Step 4: Decrypt actual ciphertext at the derived message key */
                int ic = fast_ic_m3(r0, r1, r2, mk0, mk1, mk2,
                                    0, 0, 0, sref[rf], idplug, ct, n);

                /* Boost IC score if indicator matches known operator key patterns */
                ic += op_score * 100;

                if (ic > thresh) {
                    #pragma omp critical(cand_m3_ind)
                    {
                    if (ncand < MAX_CAND) {
                        cand[ncand].ic = ic;
                        cand[ncand].r0 = r0; cand[ncand].r1 = r1; cand[ncand].r2 = r2;
                        cand[ncand].ref = sref[rf];
                        cand[ncand].p0 = mk0; cand[ncand].p1 = mk1; cand[ncand].p2 = mk2;
                        cand[ncand].g0 = 0; cand[ncand].g1 = 0; cand[ncand].g2 = 0;
                        ncand++;
                        if (ic < min_ic || ncand == 1) min_ic = ic;
                        if (ncand == MAX_CAND) {
                            min_ic = INT_MAX;
                            for (int k = 0; k < ncand; k++)
                                if (cand[k].ic < min_ic) min_ic = cand[k].ic;
                        }
                    } else if (ic > min_ic) {
                        int mi = 0;
                        for (int k = 1; k < ncand; k++)
                            if (cand[k].ic < cand[mi].ic) mi = k;
                        cand[mi] = cand[ncand-1];
                        ncand--;
                        cand[ncand].ic = ic;
                        cand[ncand].r0 = r0; cand[ncand].r1 = r1; cand[ncand].r2 = r2;
                        cand[ncand].ref = sref[rf];
                        cand[ncand].p0 = mk0; cand[ncand].p1 = mk1; cand[ncand].p2 = mk2;
                        cand[ncand].g0 = 0; cand[ncand].g1 = 0; cand[ncand].g2 = 0;
                        ncand++;
                        min_ic = INT_MAX;
                        for (int k = 0; k < ncand; k++)
                            if (cand[k].ic < min_ic) min_ic = cand[k].ic;
                    }
                    }
                }
            }
        }
    }

    double t1 = now_sec();
    fprintf(stderr, "PROGRESS:phase1:done:%lld\n", total);
    fflush(stderr);

    if (!json_mode) {
        printf("  Done: %lld configs in %.2fs (%.0f/s)\n", cnt, t1-t0, cnt/(t1-t0));
        printf("  Doubled-indicator filter passed: %lld configs (%.2f%%)\n",
               filtered, cnt > 0 ? 100.0 * filtered / cnt : 0.0);
        printf("  Candidates above IC threshold: %d\n\n", ncand);
    }

    if (ncand == 0) {
        if (!json_mode)
            printf("  *** No candidates found — indicator may be wrong ***\n");
        result.elapsed = t1 - t0;
        result.configs = cnt;
        result.german_score = -1;
        return result;
    }

    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    /* Phase 2: ring search on all candidates */
    int top_rings = ncand;
    if (!json_mode)
        printf("Phase 2: Ring search on all %d candidates (26³ = 17,576 rings each)...\n", top_rings);
    fprintf(stderr, "PROGRESS:phase2:0:%d\n", top_rings);
    fflush(stderr);

    for (int c = 0; c < top_rings; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        char tmp[512];
        m3_encrypt(r0, r1, r2, p0, p1, p2, 0, 0, 0, rf, idplug, ct, n, tmp);
        int best_fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
        int bg0 = 0, bg1 = 0, bg2 = 0;

        for (int g0 = 0; g0 < 26; g0++)
        for (int g1 = 0; g1 < 26; g1++)
        for (int g2 = 0; g2 < 26; g2++) {
            m3_encrypt(r0, r1, r2, p0, p1, p2, g0, g1, g2, rf, idplug, ct, n, tmp);
            int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
            if (fit > best_fit) {
                best_fit = fit;
                bg0 = g0; bg1 = g1; bg2 = g2;
            }
        }
        m3_encrypt(r0, r1, r2, p0, p1, p2, bg0, bg1, bg2, rf, idplug, ct, n, tmp);
        cand[c].ic = ic_num(tmp, n);
        cand[c].g0 = bg0; cand[c].g1 = bg1; cand[c].g2 = bg2;
        fprintf(stderr, "PROGRESS:phase2:%d:%d\n", c+1, top_rings);
        fflush(stderr);
    }

    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    double t2 = now_sec();
    if (!json_mode)
        printf("  Done in %.2fs\n\n", t2-t1);

    /* Phase 3: hill climb plugboard on top 10 */
    int top_hc = ncand < 10 ? ncand : 10;
    if (!json_mode)
        printf("Phase 3: Hill climb plugboard on top %d candidates\n\n", top_hc);
    fprintf(stderr, "PROGRESS:phase3:0:%d\n", top_hc);
    fflush(stderr);

    int best_gs = -1;
    int best_plug[26];
    char best_text[512];
    int bR0=0,bR1=0,bR2=0,bRef=0,bP0=0,bP1=0,bP2=0,bG0=0,bG1=0,bG2=0;

    for (int c = 0; c < top_hc; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        int bg0 = cand[c].g0, bg1 = cand[c].g1, bg2 = cand[c].g2;

        int plug[26];
        char out[512];
        int gs = hill_climb_m3(r0, r1, r2, p0, p1, p2, bg0, bg1, bg2, rf, ct, n, plug, out);

        memcpy(best_plug, plug, sizeof(plug));
        strcpy(best_text, out);

        if (!json_mode) {
            printf("  #%d  Rotors %s,%s,%s  Ref %s  Pos %c%c%c  Rings %c%c%c\n",
                   c+1, ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2],
                   REFLECTOR_NAME[rf], p0+'A', p1+'A', p2+'A',
                   bg0+'A', bg1+'A', bg2+'A');
            printf("       IC=%.4f  German=%d\n", ic_dbl(out, n), gs);
            printf("       Text: %s\n\n", best_text);
        }

        fprintf(stderr, "PROGRESS:phase3:%d:%d\n", c+1, top_hc);
        fflush(stderr);

        if (gs > best_gs) {
            best_gs = gs;
            bR0=r0; bR1=r1; bR2=r2; bRef=rf;
            bP0=p0; bP1=p1; bP2=p2;
            bG0=bg0; bG1=bg1; bG2=bg2;
        }
    }

    double t3 = now_sec();

    result.r0 = bR0; result.r1 = bR1; result.r2 = bR2;
    result.ref = bRef;
    result.p0 = bP0; result.p1 = bP1; result.p2 = bP2;
    result.g0 = bG0; result.g1 = bG1; result.g2 = bG2;
    memcpy(result.plug, best_plug, sizeof(best_plug));
    strncpy(result.text, best_text, sizeof(result.text)-1);
    result.text[sizeof(result.text)-1] = '\0';
    result.german_score = best_gs;
    result.elapsed = t3 - t0;
    result.configs = cnt;

    if (!json_mode) {
        printf("════════════════════════════════════════\n");
        printf("BEST RESULT (M3 indicator mode)\n");
        printf("════════════════════════════════════════\n");
        printf("Rotors:      %s, %s, %s (L,M,R)\n",
               ROTOR_NAME[bR0], ROTOR_NAME[bR1], ROTOR_NAME[bR2]);
        printf("Reflector:   %s\n", REFLECTOR_NAME[bRef]);
        printf("Positions:   %c%c%c  (derived message key)\n", bP0+'A', bP1+'A', bP2+'A');
        printf("Rings:       %c%c%c\n", bG0+'A', bG1+'A', bG2+'A');
        printf("Plugboard:   ");
        for (int i = 0; i < 26; i++)
            if (best_plug[i] > i) printf("%c%c ", i+'A', best_plug[i]+'A');
        printf("\nPlaintext:   %s\n", best_text);
        printf("German score: %d\n", best_gs);
        printf("Total time:  %.2fs\n", t3 - t0);
    }

    return result;
}

/* M4 indicator brute-force.
 * indicator = first 3-8 letters of ciphertext (procedure indicator)
 * ct = ciphertext AFTER stripping the indicator
 * n = length of ct
 * ind = indicator string
 * ind_n = length of indicator
 *
 * For M4, the indicator procedure is complex (K-book/bigram system).
 * We use a simplified approach: for each rotor perm × reflector ×
 * Grundstellung position, decrypt the first 3 indicator letters through
 * the Enigma. The result is the candidate message key. Then decrypt the
 * actual ciphertext at that message key and score it.
 *
 * This doesn't require the doubled indicator check (M4 didn't use that
 * procedure), but the indicator creates a verifiable relationship between
 * Grundstellung and message key that improves the fitness signal.
 */
static CrackResult brute_force_m4_indicator(
    const char *ct, int n,
    const char *ind, int ind_n,
    int json_mode)
{
    CrackResult result;
    memset(&result, 0, sizeof(result));
    result.is_m4 = 1;

    int sr[8] = {R_I, R_II, R_III, R_IV, R_V, R_VI, R_VII, R_VIII};
    int sref[2] = {REF_B_THIN, REF_C_THIN};
    int thin_rotors[2] = {R_BETA, R_GAMMA};
    int idplug[26]; plug_init(idplug);

    /* We need at least 3 indicator letters to derive a message key */
    if (ind_n < 3) {
        if (!json_mode)
            printf("M4 indicator mode requires at least 3 indicator letters (got %d)\n", ind_n);
        result.german_score = -1;
        return result;
    }

    /* Use only first 3 indicator letters for message key derivation */
    int ind_use = 3;

    int thresh = (int)(0.035 * (double)n * (n - 1));

    Cand cand[MAX_CAND];
    int ncand = 0;
    int min_ic = 0;

    /* Total: 2 thin × 26 thin_pos × 336 perms × 2 ref × 26³ Grundstellungen */
    long long total = 2LL * 26 * 336 * 2 * 26 * 26 * 26;
    if (!json_mode) {
        printf("M4 Indicator mode: message key derivation from Grundstellung\n");
        printf("Indicator (first %d letters): %c%c%c\n",
               ind_n, ind[0], ind[1], ind[2]);
        printf("Phase 1: %lld configs (2 thin × 26 thin_pos × 336 perms × 2 ref × 26³ Grundstellungen)\n", total);
    }
    fprintf(stderr, "PROGRESS:phase1:0:%lld\n", total);
    fflush(stderr);

    double t0 = now_sec();
    long long cnt = 0;

    #pragma omp parallel for collapse(2) schedule(dynamic) reduction(+:cnt) shared(cand, ncand, min_ic)
    for (int thi = 0; thi < 2; thi++)
    for (int tp = 0; tp < 26; tp++) {
        for (int ai = 0; ai < 8; ai++)
        for (int aj = 0; aj < 8; aj++) {
            if (aj == ai) continue;
            for (int ak = 0; ak < 8; ak++) {
                if (ak == ai || ak == aj) continue;
                int r0 = sr[ai], r1 = sr[aj], r2 = sr[ak];

                for (int rf = 0; rf < 2; rf++)
                for (int g0 = 0; g0 < 26; g0++)     /* Grundstellung positions */
                for (int g1 = 0; g1 < 26; g1++)
                for (int g2 = 0; g2 < 26; g2++) {
                    cnt++;

                    /* Step 1: Decrypt 3 indicator letters at this Grundstellung */
                    char ind_out[8];
                    m4_encrypt(thin_rotors[thi], r0, r1, r2,
                               tp, g0, g1, g2,
                               0, 0, 0, 0,
                               sref[rf], idplug, ind, ind_use, ind_out);

                    /* Step 2: The decrypted 3 letters are the message key */
                    int mk0 = ind_out[0] - 'A';
                    int mk1 = ind_out[1] - 'A';
                    int mk2 = ind_out[2] - 'A';

                    /* Step 2b: Score decrypted indicator against common operator keys */
                    char ind_key[4];
                    ind_key[0] = ind_out[0];
                    ind_key[1] = ind_out[1];
                    ind_key[2] = ind_out[2];
                    ind_key[3] = '\0';
                    int op_score = score_operator_key(ind_key, 3);

                    /* Step 3: Decrypt actual ciphertext at the derived message key */
                    int ic = fast_ic_m4(thin_rotors[thi], r0, r1, r2,
                                        tp, mk0, mk1, mk2,
                                        0, 0, 0, 0,
                                        sref[rf], idplug, ct, n);

                    /* Boost IC score if indicator matches known operator key patterns.
                     * A strong operator key match (score >= 50) is highly significant
                     * and should push this candidate above non-matching ones. */
                    ic += op_score * 100;

                    if (ic > thresh) {
                        #pragma omp critical(cand_m4_ind)
                        {
                        if (ncand < MAX_CAND) {
                            cand[ncand].ic = ic;
                            cand[ncand].r0 = r0; cand[ncand].r1 = r1; cand[ncand].r2 = r2;
                            cand[ncand].ref = sref[rf];
                            cand[ncand].p0 = mk0; cand[ncand].p1 = mk1; cand[ncand].p2 = mk2;
                            cand[ncand].g0 = 0; cand[ncand].g1 = 0; cand[ncand].g2 = 0;
                            cand[ncand].thin = thin_rotors[thi];
                            cand[ncand].tp = tp;
                            ncand++;
                            if (ic < min_ic || ncand == 1) min_ic = ic;
                            if (ncand == MAX_CAND) {
                                min_ic = INT_MAX;
                                for (int k = 0; k < ncand; k++)
                                    if (cand[k].ic < min_ic) min_ic = cand[k].ic;
                            }
                        } else if (ic > min_ic) {
                            int mi = 0;
                            for (int k = 1; k < ncand; k++)
                                if (cand[k].ic < cand[mi].ic) mi = k;
                            cand[mi] = cand[ncand-1];
                            ncand--;
                            cand[ncand].ic = ic;
                            cand[ncand].r0 = r0; cand[ncand].r1 = r1; cand[ncand].r2 = r2;
                            cand[ncand].ref = sref[rf];
                            cand[ncand].p0 = mk0; cand[ncand].p1 = mk1; cand[ncand].p2 = mk2;
                            cand[ncand].g0 = 0; cand[ncand].g1 = 0; cand[ncand].g2 = 0;
                            cand[ncand].thin = thin_rotors[thi];
                            cand[ncand].tp = tp;
                            ncand++;
                            min_ic = INT_MAX;
                            for (int k = 0; k < ncand; k++)
                                if (cand[k].ic < min_ic) min_ic = cand[k].ic;
                        }
                        }
                    }
                }
            }
        }
    }

    double t1 = now_sec();
    fprintf(stderr, "PROGRESS:phase1:done:%lld\n", total);
    fflush(stderr);

    if (!json_mode) {
        printf("  Done: %lld configs in %.2fs (%.0f/s)\n", cnt, t1-t0, cnt/(t1-t0));
        printf("  Candidates above IC threshold: %d\n\n", ncand);
    }

    if (ncand == 0) {
        if (!json_mode)
            printf("  *** No candidates found — indicator may be wrong ***\n");
        result.elapsed = t1 - t0;
        result.configs = cnt;
        result.german_score = -1;
        return result;
    }

    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    /* Phase 2: ring search on all candidates (26^4 including thin ring) */
    int top_rings = ncand;
    if (!json_mode)
        printf("Phase 2: Ring search on all %d candidates (26^4 = 456,976 rings each)...\n", top_rings);
    fprintf(stderr, "PROGRESS:phase2:0:%d\n", top_rings);
    fflush(stderr);

    for (int c = 0; c < top_rings; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        int thin = cand[c].thin;
        int tp = cand[c].tp;
        char tmp[512];
        m4_encrypt(thin, r0, r1, r2, tp, p0, p1, p2, 0, 0, 0, 0, rf, idplug, ct, n, tmp);
        int best_fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
        int bg0 = 0, bg1 = 0, bg2 = 0, btg = 0;

        for (int tg = 0; tg < 26; tg++)
        for (int g0 = 0; g0 < 26; g0++)
        for (int g1 = 0; g1 < 26; g1++)
        for (int g2 = 0; g2 < 26; g2++) {
            m4_encrypt(thin, r0, r1, r2, tp, p0, p1, p2, tg, g0, g1, g2, rf, idplug, ct, n, tmp);
            int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
            if (fit > best_fit) {
                best_fit = fit;
                bg0 = g0; bg1 = g1; bg2 = g2; btg = tg;
            }
        }
        m4_encrypt(thin, r0, r1, r2, tp, p0, p1, p2, btg, bg0, bg1, bg2, rf, idplug, ct, n, tmp);
        cand[c].ic = ic_num(tmp, n);
        cand[c].g0 = bg0; cand[c].g1 = bg1; cand[c].g2 = bg2;
        cand[c].tg = btg;
        fprintf(stderr, "PROGRESS:phase2:%d:%d\n", c+1, top_rings);
        fflush(stderr);
    }

    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    double t2 = now_sec();
    if (!json_mode)
        printf("  Done in %.2fs\n\n", t2-t1);

    /* Phase 3: hill climb plugboard on top 10 */
    int top_hc = ncand < 10 ? ncand : 10;
    if (!json_mode)
        printf("Phase 3: Hill climb plugboard on top %d candidates\n\n", top_hc);
    fprintf(stderr, "PROGRESS:phase3:0:%d\n", top_hc);
    fflush(stderr);

    int best_gs = -1;
    int best_plug[26];
    char best_text[512];
    int bThin=R_BETA, bR0=0,bR1=0,bR2=0,bRef=0,bP0=0,bP1=0,bP2=0,bTp=0;
    int bG0=0,bG1=0,bG2=0,bTg=0;

    for (int c = 0; c < top_hc; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        int thin = cand[c].thin;
        int tp = cand[c].tp;
        int bg0 = cand[c].g0, bg1 = cand[c].g1, bg2 = cand[c].g2;
        int btg = cand[c].tg;

        int plug[26];
        char out[512];
        int gs = hill_climb_m4(thin, r0, r1, r2, tp, p0, p1, p2, btg, bg0, bg1, bg2, rf, ct, n, plug, out);

        memcpy(best_plug, plug, sizeof(plug));
        strcpy(best_text, out);

        if (!json_mode) {
            printf("  #%d  Thin %s  Rotors %s,%s,%s  Ref %s  ThinPos %c  Pos %c%c%c  Rings %c%c%c%c\n",
                   c+1, ROTOR_NAME[thin],
                   ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2],
                   REFLECTOR_NAME[rf], tp+'A',
                   p0+'A', p1+'A', p2+'A',
                   btg+'A', bg0+'A', bg1+'A', bg2+'A');
            printf("       IC=%.4f  German=%d\n", ic_dbl(out, n), gs);
            printf("       Text: %s\n\n", best_text);
        }

        fprintf(stderr, "PROGRESS:phase3:%d:%d\n", c+1, top_hc);
        fflush(stderr);

        if (gs > best_gs) {
            best_gs = gs;
            bThin = thin;
            bR0=r0; bR1=r1; bR2=r2; bRef=rf;
            bTp=tp; bP0=p0; bP1=p1; bP2=p2;
            bG0=bg0; bG1=bg1; bG2=bg2; bTg=btg;
        }
    }

    double t3 = now_sec();

    result.thin = bThin;
    result.r0 = bR0; result.r1 = bR1; result.r2 = bR2;
    result.ref = bRef;
    result.tp = bTp;
    result.p0 = bP0; result.p1 = bP1; result.p2 = bP2;
    result.g0 = bG0; result.g1 = bG1; result.g2 = bG2;
    result.tg = bTg;
    memcpy(result.plug, best_plug, sizeof(best_plug));
    strncpy(result.text, best_text, sizeof(result.text)-1);
    result.text[sizeof(result.text)-1] = '\0';
    result.german_score = best_gs;
    result.elapsed = t3 - t0;
    result.configs = cnt;

    if (!json_mode) {
        printf("════════════════════════════════════════\n");
        printf("BEST RESULT (M4 indicator mode)\n");
        printf("════════════════════════════════════════\n");
        printf("Thin rotor:  %s\n", ROTOR_NAME[bThin]);
        printf("Rotors:      %s, %s, %s (L,M,R)\n",
               ROTOR_NAME[bR0], ROTOR_NAME[bR1], ROTOR_NAME[bR2]);
        printf("Reflector:   %s\n", REFLECTOR_NAME[bRef]);
        printf("Thin Pos:    %c\n", bTp+'A');
        printf("Positions:   %c%c%c  (derived message key)\n", bP0+'A', bP1+'A', bP2+'A');
        printf("Rings:       %c%c%c%c\n", bTg+'A', bG0+'A', bG1+'A', bG2+'A');
        printf("Plugboard:   ");
        for (int i = 0; i < 26; i++)
            if (best_plug[i] > i) printf("%c%c ", i+'A', best_plug[i]+'A');
        printf("\nPlaintext:   %s\n", best_text);
        printf("German score: %d\n", best_gs);
        printf("Total time:  %.2fs\n", t3 - t0);
    }

    return result;
}

/* ────────────────────────────────────────────────────────── */
/*  Baseline search mode                                      */
/*                                                            */
/*  Exploits the German weakness of making small incremental  */
/*  changes to daily settings. Instead of searching all       */
/*  26^4 ring combinations, search ±2 positions from a       */
/*  known baseline. Also searches rotor positions ±2 and     */
/*  plugboard by swapping 1-2 pairs from the baseline.       */
/*                                                            */
/*  Baseline format:                                          */
/*    rotors:beta,II,IV,I,reflector:B_thin,rings:AAFB,        */
/*    plugboard:CP,DG,EJ,FI,KT,LZ,MS                          */
/* ────────────────────────────────────────────────────────── */

/* Parse a rotor name string into rotor index */
static int parse_rotor_name(const char *name)
{
    for (int i = 0; i < 10; i++) {
        if (strcmp(ROTOR_NAME[i], name) == 0)
            return i;
    }
    return -1;
}

/* Parse a reflector name string into reflector index */
static int parse_reflector_name(const char *name)
{
    for (int i = 0; i < 4; i++) {
        if (strcmp(REFLECTOR_NAME[i], name) == 0)
            return i;
    }
    return -1;
}

/* Baseline settings structure */
typedef struct {
    int thin;           /* thin rotor (M4 only) */
    int r0, r1, r2;     /* left, middle, right rotors */
    int ref;            /* reflector */
    int tg, g0, g1, g2; /* ring settings (thin, left, middle, right) */
    int tp, p0, p1, p2; /* positions (thin, left, middle, right) */
    int plug[26];       /* plugboard */
    int has_positions;  /* whether positions are specified */
    int is_m4;
} BaselineSettings;

/* Parse baseline settings string.
 * Format: rotors:beta,II,IV,I,reflector:B_thin,rings:AAFB,plugboard:CP,DG,...
 *         positions:VJNA (optional)
 * Returns 1 on success, 0 on failure.
 */
static int parse_baseline(const char *str, BaselineSettings *bs)
{
    memset(bs, 0, sizeof(*bs));
    plug_init(bs->plug);
    bs->thin = -1;
    bs->has_positions = 0;

    /* Make a mutable copy */
    char buf[512];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Split by commas at the top level, but first split by section keywords */
    char *p = buf;
    while (*p) {
        /* Find the section keyword (rotors:, reflector:, rings:, plugboard:, positions:) */
        char *section = p;
        char *colon = strchr(p, ':');
        if (!colon) break;
        *colon = '\0';
        char *value = colon + 1;

        /* Find end of value (next section keyword or end of string) */
        /* Sections are delimited by commas followed by a keyword and colon */
        char *next = value;
        /* Find the next section: look for a comma that's followed by a word and colon */
        char *search = value;
        while (*search) {
            char *comma = strchr(search, ',');
            if (!comma) { next = search + strlen(search); break; }
            /* Check if what follows the comma looks like "keyword:" */
            char *after = comma + 1;
            char *next_colon = strchr(after, ':');
            if (next_colon) {
                /* Check that everything between comma and colon is alpha */
                int is_section = 1;
                for (char *c = after; c < next_colon; c++) {
                    if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z'))) {
                        is_section = 0;
                        break;
                    }
                }
                if (is_section) {
                    *comma = '\0';
                    next = after;
                    break;
                }
            }
            search = comma + 1;
        }
        if (!*next) next = value + strlen(value);

        /* Process the section */
        if (strcmp(section, "rotors") == 0) {
            /* Parse comma-separated rotor names: beta,II,IV,I (M4) or I,II,III (M3) */
            char rotors[4][16];
            int nrot = 0;
            char *tok = strtok(value, ",");
            while (tok && nrot < 4) {
                strncpy(rotors[nrot], tok, sizeof(rotors[0]) - 1);
                rotors[nrot][sizeof(rotors[0]) - 1] = '\0';
                nrot++;
                tok = strtok(NULL, ",");
            }
            if (nrot == 4) {
                /* M4: thin,left,middle,right */
                bs->is_m4 = 1;
                bs->thin = parse_rotor_name(rotors[0]);
                bs->r0 = parse_rotor_name(rotors[1]);
                bs->r1 = parse_rotor_name(rotors[2]);
                bs->r2 = parse_rotor_name(rotors[3]);
            } else if (nrot == 3) {
                /* M3: left,middle,right */
                bs->is_m4 = 0;
                bs->r0 = parse_rotor_name(rotors[0]);
                bs->r1 = parse_rotor_name(rotors[1]);
                bs->r2 = parse_rotor_name(rotors[2]);
            }
        } else if (strcmp(section, "reflector") == 0) {
            bs->ref = parse_reflector_name(value);
        } else if (strcmp(section, "rings") == 0) {
            int rlen = (int)strlen(value);
            if (bs->is_m4 && rlen >= 4) {
                bs->tg = value[0] - 'A';
                bs->g0 = value[1] - 'A';
                bs->g1 = value[2] - 'A';
                bs->g2 = value[3] - 'A';
            } else if (rlen >= 3) {
                bs->g0 = value[0] - 'A';
                bs->g1 = value[1] - 'A';
                bs->g2 = value[2] - 'A';
            }
        } else if (strcmp(section, "plugboard") == 0) {
            char *tok = strtok(value, ",");
            while (tok) {
                if (strlen(tok) >= 2) {
                    int a = tok[0] - 'A';
                    int b = tok[1] - 'A';
                    if (a >= 0 && a < 26 && b >= 0 && b < 26)
                        plug_add(bs->plug, a, b);
                }
                tok = strtok(NULL, ",");
            }
        } else if (strcmp(section, "positions") == 0) {
            int plen = (int)strlen(value);
            if (bs->is_m4 && plen >= 4) {
                bs->tp = value[0] - 'A';
                bs->p0 = value[1] - 'A';
                bs->p1 = value[2] - 'A';
                bs->p2 = value[3] - 'A';
                bs->has_positions = 1;
            } else if (plen >= 3) {
                bs->p0 = value[0] - 'A';
                bs->p1 = value[1] - 'A';
                bs->p2 = value[2] - 'A';
                bs->has_positions = 1;
            }
        }

        p = next;
    }

    /* Validate */
    if (bs->r0 < 0 || bs->r1 < 0 || bs->r2 < 0 || bs->ref < 0)
        return 0;
    if (bs->is_m4 && bs->thin < 0)
        return 0;

    return 1;
}

/* Generate ±2 range for a ring/position value (wrapping at 26) */
static void range_pm2(int center, int *vals, int *count)
{
    *count = 0;
    for (int d = -2; d <= 2; d++) {
        vals[(*count)++] = ((center + d) % 26 + 26) % 26;
    }
}

/* Baseline search for M3 */
static CrackResult baseline_search_m3(
    const char *ct, int n,
    const BaselineSettings *bs,
    int json_mode)
{
    CrackResult result;
    memset(&result, 0, sizeof(result));
    result.is_m4 = 0;

    int r0 = bs->r0, r1 = bs->r1, r2 = bs->r2;
    int ref = bs->ref;
    int bg0 = bs->g0, bg1 = bs->g1, bg2 = bs->g2;

    /* Generate ±2 ranges for rings */
    int rg0[5], rg1[5], rg2[5];
    int ng0, ng1, ng2;
    range_pm2(bg0, rg0, &ng0);
    range_pm2(bg1, rg1, &ng1);
    range_pm2(bg2, rg2, &ng2);

    /* Generate ±2 ranges for positions (if provided, otherwise search all 26) */
    int rp0[26], rp1[26], rp2[26];
    int np0, np1, np2;
    if (bs->has_positions) {
        range_pm2(bs->p0, rp0, &np0);
        range_pm2(bs->p1, rp1, &np1);
        range_pm2(bs->p2, rp2, &np2);
    } else {
        np0 = np1 = np2 = 26;
        for (int i = 0; i < 26; i++) { rp0[i] = i; rp1[i] = i; rp2[i] = i; }
    }

    long long total = (long long)ng0 * ng1 * ng2 * np0 * np1 * np2;
    if (!json_mode) {
        printf("M3 Baseline search mode: ±2 from known settings\n");
        printf("Baseline rotors: %s,%s,%s  Ref: %s  Rings: %c%c%c\n",
               ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2],
               REFLECTOR_NAME[ref], bg0+'A', bg1+'A', bg2+'A');
        if (bs->has_positions)
            printf("Baseline positions: %c%c%c\n", bs->p0+'A', bs->p1+'A', bs->p2+'A');
        printf("Search space: %lld configs (rings ±2 × positions ±2)\n", total);
    }
    fprintf(stderr, "PROGRESS:phase1:0:%lld\n", total);
    fflush(stderr);

    double t0 = now_sec();
    long long cnt = 0;

    int best_plug[26];
    memcpy(best_plug, bs->plug, sizeof(best_plug));
    char best_text[512];
    int best_fit = -1;
    int bP0=0, bP1=0, bP2=0, bG0=0, bG1=0, bG2=0;

    /* Phase 1: Search rings ±2 × positions ±2 with baseline plugboard */
    #pragma omp parallel for collapse(3) schedule(dynamic) reduction(+:cnt) \
        shared(best_fit, best_plug, best_text, bP0, bP1, bP2, bG0, bG1, bG2)
    for (int i0 = 0; i0 < ng0; i0++)
    for (int i1 = 0; i1 < ng1; i1++)
    for (int i2 = 0; i2 < ng2; i2++) {
        int g0 = rg0[i0], g1 = rg1[i1], g2 = rg2[i2];
        for (int j0 = 0; j0 < np0; j0++)
        for (int j1 = 0; j1 < np1; j1++)
        for (int j2 = 0; j2 < np2; j2++) {
            int p0 = rp0[j0], p1 = rp1[j1], p2 = rp2[j2];
            cnt++;

            char tmp[512];
            m3_encrypt(r0, r1, r2, p0, p1, p2, g0, g1, g2, ref,
                       bs->plug, ct, n, tmp);
            int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);

            if (fit > best_fit) {
                #pragma omp critical(baseline_m3)
                {
                if (fit > best_fit) {
                    best_fit = fit;
                    bP0 = p0; bP1 = p1; bP2 = p2;
                    bG0 = g0; bG1 = g1; bG2 = g2;
                    memcpy(best_plug, bs->plug, sizeof(best_plug));
                    strncpy(best_text, tmp, sizeof(best_text) - 1);
                    best_text[sizeof(best_text) - 1] = '\0';
                }
                }
            }
        }
    }

    double t1 = now_sec();
    fprintf(stderr, "PROGRESS:phase1:done:%lld\n", total);
    fflush(stderr);
    if (!json_mode)
        printf("  Phase 1 done: %lld configs in %.2fs\n", cnt, t1 - t0);

    /* Phase 2: Plugboard swap search — try swapping 1-2 pairs from baseline */
    int base_plug[26];
    memcpy(base_plug, bs->plug, sizeof(base_plug));

    /* Count baseline pairs */
    int base_pairs[13][2];
    int nbase_pairs = 0;
    for (int i = 0; i < 26; i++) {
        if (base_plug[i] > i) {
            base_pairs[nbase_pairs][0] = i;
            base_pairs[nbase_pairs][1] = base_plug[i];
            nbase_pairs++;
        }
    }

    /* Phase 2a: Try removing each baseline pair */
    long long p2_count = 0;
    if (!json_mode)
        printf("Phase 2: Plugboard swap search (±1-2 pairs from baseline)...\n");
    fprintf(stderr, "PROGRESS:phase2:0:%d\n", nbase_pairs + 1);
    fflush(stderr);

    /* Start from best Phase 1 result */
    int cur_plug[26];
    memcpy(cur_plug, base_plug, sizeof(cur_plug));

    /* Try the baseline plugboard as-is with best positions/rings */
    {
        char tmp[512];
        m3_encrypt(r0, r1, r2, bP0, bP1, bP2, bG0, bG1, bG2, ref,
                   base_plug, ct, n, tmp);
        int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
        if (fit > best_fit) {
            best_fit = fit;
            memcpy(best_plug, base_plug, sizeof(best_plug));
            strncpy(best_text, tmp, sizeof(best_text) - 1);
            best_text[sizeof(best_text) - 1] = '\0';
        }
    }

    /* Try removing each pair */
    for (int pi = 0; pi < nbase_pairs; pi++) {
        int trial_plug[26];
        memcpy(trial_plug, base_plug, sizeof(trial_plug));
        int a = base_pairs[pi][0], b = base_pairs[pi][1];
        trial_plug[a] = a;
        trial_plug[b] = b;

        char tmp[512];
        m3_encrypt(r0, r1, r2, bP0, bP1, bP2, bG0, bG1, bG2, ref,
                   trial_plug, ct, n, tmp);
        int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
        p2_count++;
        if (fit > best_fit) {
            best_fit = fit;
            memcpy(best_plug, trial_plug, sizeof(trial_plug));
            strncpy(best_text, tmp, sizeof(best_text) - 1);
            best_text[sizeof(best_text) - 1] = '\0';
        }
        fprintf(stderr, "PROGRESS:phase2:%d:%d\n", pi + 1, nbase_pairs + 1);
        fflush(stderr);
    }

    /* Try adding new pairs (swapping unused letters) */
    int used[26] = {0};
    for (int i = 0; i < 26; i++) {
        if (base_plug[i] != i) { used[i] = 1; }
    }

    for (int a = 0; a < 26; a++) {
        if (used[a]) continue;
        for (int b = a + 1; b < 26; b++) {
            if (used[b]) continue;
            int trial_plug[26];
            memcpy(trial_plug, best_plug, sizeof(trial_plug));
            trial_plug[a] = b;
            trial_plug[b] = a;

            char tmp[512];
            m3_encrypt(r0, r1, r2, bP0, bP1, bP2, bG0, bG1, bG2, ref,
                       trial_plug, ct, n, tmp);
            int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
            p2_count++;
            if (fit > best_fit) {
                best_fit = fit;
                memcpy(best_plug, trial_plug, sizeof(trial_plug));
                strncpy(best_text, tmp, sizeof(best_text) - 1);
                best_text[sizeof(best_text) - 1] = '\0';
            }
        }
    }

    /* Phase 3: Hill climb from best found so far */
    if (!json_mode)
        printf("Phase 3: Hill climb plugboard refinement...\n");
    fprintf(stderr, "PROGRESS:phase3:0:1\n");
    fflush(stderr);

    int hc_plug[26];
    char hc_out[512];
    int gs = hill_climb_m3(r0, r1, r2, bP0, bP1, bP2, bG0, bG1, bG2, ref,
                           ct, n, hc_plug, hc_out);

    if (gs > best_fit) {
        best_fit = gs;
        memcpy(best_plug, hc_plug, sizeof(hc_plug));
        strncpy(best_text, hc_out, sizeof(best_text) - 1);
        best_text[sizeof(best_text) - 1] = '\0';
    }

    double t2 = now_sec();
    fprintf(stderr, "PROGRESS:phase3:done:1\n");
    fflush(stderr);

    result.r0 = r0; result.r1 = r1; result.r2 = r2;
    result.ref = ref;
    result.p0 = bP0; result.p1 = bP1; result.p2 = bP2;
    result.g0 = bG0; result.g1 = bG1; result.g2 = bG2;
    memcpy(result.plug, best_plug, sizeof(best_plug));
    strncpy(result.text, best_text, sizeof(result.text) - 1);
    result.text[sizeof(result.text) - 1] = '\0';
    result.german_score = best_fit;
    result.elapsed = t2 - t0;
    result.configs = cnt + p2_count;

    if (!json_mode) {
        printf("\n════════════════════════════════════════\n");
        printf("BEST RESULT (M3 baseline search)\n");
        printf("════════════════════════════════════════\n");
        printf("Rotors:      %s, %s, %s (L,M,R)\n",
               ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2]);
        printf("Reflector:   %s\n", REFLECTOR_NAME[ref]);
        printf("Positions:   %c%c%c\n", bP0+'A', bP1+'A', bP2+'A');
        printf("Rings:       %c%c%c\n", bG0+'A', bG1+'A', bG2+'A');
        printf("Plugboard:   ");
        for (int i = 0; i < 26; i++)
            if (best_plug[i] > i) printf("%c%c ", i+'A', best_plug[i]+'A');
        printf("\nPlaintext:   %s\n", best_text);
        printf("German score: %d\n", best_fit);
        printf("Total time:  %.2fs\n", t2 - t0);
        printf("Configs:     %lld\n", cnt + p2_count);
    }

    return result;
}

/* Baseline search for M4 */
static CrackResult baseline_search_m4(
    const char *ct, int n,
    const BaselineSettings *bs,
    int json_mode)
{
    CrackResult result;
    memset(&result, 0, sizeof(result));
    result.is_m4 = 1;

    int thin = bs->thin;
    int r0 = bs->r0, r1 = bs->r1, r2 = bs->r2;
    int ref = bs->ref;
    int btg = bs->tg, bg0 = bs->g0, bg1 = bs->g1, bg2 = bs->g2;

    /* Generate ±2 ranges for rings (including thin ring) */
    int rtg[5], rg0[5], rg1[5], rg2[5];
    int ntg, ng0, ng1, ng2;
    range_pm2(btg, rtg, &ntg);
    range_pm2(bg0, rg0, &ng0);
    range_pm2(bg1, rg1, &ng1);
    range_pm2(bg2, rg2, &ng2);

    /* Generate ±2 ranges for positions */
    int rtp[26], rp0[26], rp1[26], rp2[26];
    int ntp, np0, np1, np2;
    if (bs->has_positions) {
        range_pm2(bs->tp, rtp, &ntp);
        range_pm2(bs->p0, rp0, &np0);
        range_pm2(bs->p1, rp1, &np1);
        range_pm2(bs->p2, rp2, &np2);
    } else {
        ntp = 26; for (int i = 0; i < 26; i++) rtp[i] = i;
        np0 = np1 = np2 = 26;
        for (int i = 0; i < 26; i++) { rp0[i] = i; rp1[i] = i; rp2[i] = i; }
    }

    long long total = (long long)ntg * ng0 * ng1 * ng2 * ntp * np0 * np1 * np2;
    if (!json_mode) {
        printf("M4 Baseline search mode: ±2 from known settings\n");
        printf("Baseline thin: %s  Rotors: %s,%s,%s  Ref: %s\n",
               ROTOR_NAME[thin], ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2],
               REFLECTOR_NAME[ref]);
        printf("Baseline rings: %c%c%c%c\n", btg+'A', bg0+'A', bg1+'A', bg2+'A');
        if (bs->has_positions)
            printf("Baseline positions: %c%c%c%c\n", bs->tp+'A', bs->p0+'A', bs->p1+'A', bs->p2+'A');
        printf("Search space: %lld configs (rings ±2 × positions ±2)\n", total);
    }
    fprintf(stderr, "PROGRESS:phase1:0:%lld\n", total);
    fflush(stderr);

    double t0 = now_sec();
    long long cnt = 0;

    int best_plug[26];
    memcpy(best_plug, bs->plug, sizeof(best_plug));
    char best_text[512];
    int best_fit = -1;
    int bTp=0, bP0=0, bP1=0, bP2=0;
    int bTg=0, bG0=0, bG1=0, bG2=0;

    /* Phase 1: Search rings ±2 × positions ±2 with baseline plugboard */
    #pragma omp parallel for collapse(4) schedule(dynamic) reduction(+:cnt) \
        shared(best_fit, best_plug, best_text, bTp, bP0, bP1, bP2, bTg, bG0, bG1, bG2)
    for (int itg = 0; itg < ntg; itg++)
    for (int i0 = 0; i0 < ng0; i0++)
    for (int i1 = 0; i1 < ng1; i1++)
    for (int i2 = 0; i2 < ng2; i2++) {
        int tg = rtg[itg], g0 = rg0[i0], g1 = rg1[i1], g2 = rg2[i2];
        for (int jtp = 0; jtp < ntp; jtp++)
        for (int j0 = 0; j0 < np0; j0++)
        for (int j1 = 0; j1 < np1; j1++)
        for (int j2 = 0; j2 < np2; j2++) {
            int tp = rtp[jtp], p0 = rp0[j0], p1 = rp1[j1], p2 = rp2[j2];
            cnt++;

            char tmp[512];
            m4_encrypt(thin, r0, r1, r2, tp, p0, p1, p2,
                       tg, g0, g1, g2, ref,
                       bs->plug, ct, n, tmp);
            int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);

            if (fit > best_fit) {
                #pragma omp critical(baseline_m4)
                {
                if (fit > best_fit) {
                    best_fit = fit;
                    bTp = tp; bP0 = p0; bP1 = p1; bP2 = p2;
                    bTg = tg; bG0 = g0; bG1 = g1; bG2 = g2;
                    memcpy(best_plug, bs->plug, sizeof(best_plug));
                    strncpy(best_text, tmp, sizeof(best_text) - 1);
                    best_text[sizeof(best_text) - 1] = '\0';
                }
                }
            }
        }
    }

    double t1 = now_sec();
    fprintf(stderr, "PROGRESS:phase1:done:%lld\n", total);
    fflush(stderr);
    if (!json_mode)
        printf("  Phase 1 done: %lld configs in %.2fs\n", cnt, t1 - t0);

    /* Phase 2: Plugboard swap search */
    int base_plug[26];
    memcpy(base_plug, bs->plug, sizeof(base_plug));

    int base_pairs[13][2];
    int nbase_pairs = 0;
    for (int i = 0; i < 26; i++) {
        if (base_plug[i] > i) {
            base_pairs[nbase_pairs][0] = i;
            base_pairs[nbase_pairs][1] = base_plug[i];
            nbase_pairs++;
        }
    }

    long long p2_count = 0;
    if (!json_mode)
        printf("Phase 2: Plugboard swap search (±1-2 pairs from baseline)...\n");
    fprintf(stderr, "PROGRESS:phase2:0:%d\n", nbase_pairs + 1);
    fflush(stderr);

    /* Try baseline plugboard with best positions/rings */
    {
        char tmp[512];
        m4_encrypt(thin, r0, r1, r2, bTp, bP0, bP1, bP2,
                   bTg, bG0, bG1, bG2, ref,
                   base_plug, ct, n, tmp);
        int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
        if (fit > best_fit) {
            best_fit = fit;
            memcpy(best_plug, base_plug, sizeof(best_plug));
            strncpy(best_text, tmp, sizeof(best_text) - 1);
            best_text[sizeof(best_text) - 1] = '\0';
        }
    }

    /* Try removing each baseline pair */
    for (int pi = 0; pi < nbase_pairs; pi++) {
        int trial_plug[26];
        memcpy(trial_plug, base_plug, sizeof(trial_plug));
        int a = base_pairs[pi][0], b = base_pairs[pi][1];
        trial_plug[a] = a;
        trial_plug[b] = b;

        char tmp[512];
        m4_encrypt(thin, r0, r1, r2, bTp, bP0, bP1, bP2,
                   bTg, bG0, bG1, bG2, ref,
                   trial_plug, ct, n, tmp);
        int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
        p2_count++;
        if (fit > best_fit) {
            best_fit = fit;
            memcpy(best_plug, trial_plug, sizeof(trial_plug));
            strncpy(best_text, tmp, sizeof(best_text) - 1);
            best_text[sizeof(best_text) - 1] = '\0';
        }
        fprintf(stderr, "PROGRESS:phase2:%d:%d\n", pi + 1, nbase_pairs + 1);
        fflush(stderr);
    }

    /* Try adding new pairs */
    int used[26] = {0};
    for (int i = 0; i < 26; i++) {
        if (base_plug[i] != i) used[i] = 1;
    }
    for (int a = 0; a < 26; a++) {
        if (used[a]) continue;
        for (int b = a + 1; b < 26; b++) {
            if (used[b]) continue;
            int trial_plug[26];
            memcpy(trial_plug, best_plug, sizeof(trial_plug));
            trial_plug[a] = b;
            trial_plug[b] = a;

            char tmp[512];
            m4_encrypt(thin, r0, r1, r2, bTp, bP0, bP1, bP2,
                       bTg, bG0, bG1, bG2, ref,
                       trial_plug, ct, n, tmp);
            int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
            p2_count++;
            if (fit > best_fit) {
                best_fit = fit;
                memcpy(best_plug, trial_plug, sizeof(trial_plug));
                strncpy(best_text, tmp, sizeof(best_text) - 1);
                best_text[sizeof(best_text) - 1] = '\0';
            }
        }
    }

    /* Phase 3: Hill climb from best found */
    if (!json_mode)
        printf("Phase 3: Hill climb plugboard refinement...\n");
    fprintf(stderr, "PROGRESS:phase3:0:1\n");
    fflush(stderr);

    int hc_plug[26];
    char hc_out[512];
    int gs = hill_climb_m4(thin, r0, r1, r2, bTp, bP0, bP1, bP2,
                           bTg, bG0, bG1, bG2, ref,
                           ct, n, hc_plug, hc_out);

    if (gs > best_fit) {
        best_fit = gs;
        memcpy(best_plug, hc_plug, sizeof(hc_plug));
        strncpy(best_text, hc_out, sizeof(best_text) - 1);
        best_text[sizeof(best_text) - 1] = '\0';
    }

    double t2 = now_sec();
    fprintf(stderr, "PROGRESS:phase3:done:1\n");
    fflush(stderr);

    result.thin = thin;
    result.r0 = r0; result.r1 = r1; result.r2 = r2;
    result.ref = ref;
    result.tp = bTp; result.p0 = bP0; result.p1 = bP1; result.p2 = bP2;
    result.tg = bTg; result.g0 = bG0; result.g1 = bG1; result.g2 = bG2;
    memcpy(result.plug, best_plug, sizeof(best_plug));
    strncpy(result.text, best_text, sizeof(result.text) - 1);
    result.text[sizeof(result.text) - 1] = '\0';
    result.german_score = best_fit;
    result.elapsed = t2 - t0;
    result.configs = cnt + p2_count;

    if (!json_mode) {
        printf("\n════════════════════════════════════════\n");
        printf("BEST RESULT (M4 baseline search)\n");
        printf("════════════════════════════════════════\n");
        printf("Thin rotor:  %s\n", ROTOR_NAME[thin]);
        printf("Rotors:      %s, %s, %s (L,M,R)\n",
               ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2]);
        printf("Reflector:   %s\n", REFLECTOR_NAME[ref]);
        printf("Thin Pos:    %c\n", bTp+'A');
        printf("Positions:   %c%c%c\n", bP0+'A', bP1+'A', bP2+'A');
        printf("Rings:       %c%c%c%c\n", bTg+'A', bG0+'A', bG1+'A', bG2+'A');
        printf("Plugboard:   ");
        for (int i = 0; i < 26; i++)
            if (best_plug[i] > i) printf("%c%c ", i+'A', best_plug[i]+'A');
        printf("\nPlaintext:   %s\n", best_text);
        printf("German score: %d\n", best_fit);
        printf("Total time:  %.2fs\n", t2 - t0);
        printf("Configs:     %lld\n", cnt + p2_count);
    }

    return result;
}

/* ────────────────────────────────────────────────────────── */
/*  JSON output                                               */
/* ────────────────────────────────────────────────────────── */

static void print_json_result(const CrackResult *r)
{
    printf("{\n");
    printf("  \"mode\": \"%s\",\n", r->is_m4 ? "M4" : "M3");
    printf("  \"plaintext\": \"%s\",\n", r->text);
    printf("  \"german_score\": %d,\n", r->german_score);
    printf("  \"elapsed_time\": %.4f,\n", r->elapsed);
    printf("  \"configs_tried\": %lld,\n", r->configs);

    if (r->is_m4) {
        printf("  \"thin_rotor\": \"%s\",\n", ROTOR_NAME[r->thin]);
        printf("  \"thin_position\": \"%c\",\n", r->tp + 'A');
        printf("  \"thin_ring\": \"%c\",\n", r->tg + 'A');
    }

    printf("  \"rotors\": \"%s, %s, %s\",\n",
           ROTOR_NAME[r->r0], ROTOR_NAME[r->r1], ROTOR_NAME[r->r2]);
    printf("  \"reflector\": \"%s\",\n", REFLECTOR_NAME[r->ref]);
    printf("  \"positions\": \"%c%c%c\",\n",
           r->p0+'A', r->p1+'A', r->p2+'A');

    if (r->is_m4)
        printf("  \"rings\": \"%c%c%c%c\",\n", r->tg+'A', r->g0+'A', r->g1+'A', r->g2+'A');
    else
        printf("  \"rings\": \"%c%c%c\",\n",
               r->g0+'A', r->g1+'A', r->g2+'A');

    /* Plugboard as space-separated pairs */
    printf("  \"plugboard\": \"");
    int first = 1;
    for (int i = 0; i < 26; i++) {
        if (r->plug[i] > i) {
            if (!first) printf(" ");
            printf("%c%c", i+'A', r->plug[i]+'A');
            first = 0;
        }
    }
    printf("\",\n");

    printf("  \"success\": %s\n", r->german_score >= 0 ? "true" : "false");
    printf("}\n");
}

/* ────────────────────────────────────────────────────────── */
/*  Main — CLI argument parsing                               */
/* ────────────────────────────────────────────────────────── */

/* Sanitize: uppercase, strip non-alpha, cap at 511 chars */
static int sanitize_ct(const char *in, char *out, int maxsize)
{
    int n = 0;
    for (int i = 0; in[i] && n < maxsize - 1; i++) {
        char c = in[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c >= 'A' && c <= 'Z') out[n++] = c;
    }
    out[n] = '\0';
    return n;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  --ct <TEXT>        Ciphertext to crack (uppercase A-Z only)\n"
        "  --stdin            Read ciphertext from stdin\n"
        "  --mode M3|M4       Enigma model (default: M3)\n"
        "  --indicator <TXT>  Indicator groups (first 6-8 letters of ciphertext)\n"
        "                     M3: 6-letter doubled indicator (message key sent twice)\n"
        "                     M4: 3-8 letter indicator for message key derivation\n"
        "                     The indicator is stripped from ciphertext before cracking\n"
        "                     Decrypted indicator is scored against common operator keys\n"
        "  --baseline <TXT>   Baseline settings for incremental search\n"
        "                     Format: rotors:beta,II,IV,I,reflector:B_thin,\n"
        "                             rings:AAFB,plugboard:CP,DG,...,positions:VJNA\n"
        "                     Searches ±2 from baseline (rings, positions, plugboard)\n"
        "  --format text|json Output format (default: text)\n"
        "  --help             Show this help\n"
        "\n"
        "If no --ct or --stdin is given, runs self-test mode.\n"
        "\n"
        "Examples:\n"
        "  %s --ct NCZWVUSXPNYMINHZXMQXSFWXWLKJAHSHNMCOCCAKUQPMKCSMHKSEINJUSBLK --mode M4\n"
        "  %s --ct CIPHERTEXT --mode M3 --indicator ABCDEF\n"
        "  %s --ct CIPHERTEXT --mode M4 --baseline \"rotors:gamma,V,II,VIII,reflector:C_thin,rings:AAFB,plugboard:CP,DG,EJ,FI,KT,LZ,MS\"\n"
        "  echo NCZWVUSXPNYMINHZXMQXSFWXWLKJAHSHNMCOCCAKUQPMKCSMHKSEINJUSBLK | %s --stdin --mode M4 --format json\n",
        prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    init_tables();
    load_dictionary_auto();

    /* Parse arguments */
    const char *ct_arg = NULL;
    int use_stdin = 0;
    const char *mode_str = "M3";
    const char *format_str = "text";
    const char *indicator_arg = NULL;
    const char *baseline_arg = NULL;
    int json_mode = 0;
    int is_m4 = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ct") == 0 && i + 1 < argc) {
            ct_arg = argv[++i];
        } else if (strcmp(argv[i], "--stdin") == 0) {
            use_stdin = 1;
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode_str = argv[++i];
        } else if (strcmp(argv[i], "--baseline") == 0 && i + 1 < argc) {
            baseline_arg = argv[++i];
        } else if (strcmp(argv[i], "--indicator") == 0 && i + 1 < argc) {
            indicator_arg = argv[++i];
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            format_str = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Parse mode */
    if (strcmp(mode_str, "M4") == 0 || strcmp(mode_str, "m4") == 0) {
        is_m4 = 1;
    } else if (strcmp(mode_str, "M3") == 0 || strcmp(mode_str, "m3") == 0) {
        is_m4 = 0;
    } else {
        fprintf(stderr, "Invalid mode: %s (use M3 or M4)\n", mode_str);
        return 1;
    }

    /* Parse format */
    if (strcmp(format_str, "json") == 0) {
        json_mode = 1;
    } else if (strcmp(format_str, "text") == 0) {
        json_mode = 0;
    } else {
        fprintf(stderr, "Invalid format: %s (use text or json)\n", format_str);
        return 1;
    }

    /* Get ciphertext */
    char ct_raw[2048];
    char ct[512];
    int ct_n = 0;

    if (ct_arg != NULL) {
        strncpy(ct_raw, ct_arg, sizeof(ct_raw) - 1);
        ct_raw[sizeof(ct_raw) - 1] = '\0';
        ct_n = sanitize_ct(ct_raw, ct, 512);
    } else if (use_stdin) {
        if (fgets(ct_raw, sizeof(ct_raw), stdin) == NULL) {
            fprintf(stderr, "Error: no input on stdin\n");
            return 1;
        }
        ct_n = sanitize_ct(ct_raw, ct, 512);
    } else {
        /* No ciphertext provided → self-test mode */
        ct_n = -1;  /* sentinel */
    }

    /* Parse indicator (if provided) */
    char indicator[32];
    int ind_n = 0;
    if (indicator_arg) {
        ind_n = sanitize_ct(indicator_arg, indicator, sizeof(indicator));
        if (ind_n == 0) {
            fprintf(stderr, "Error: indicator is empty after sanitizing\n");
            return 1;
        }
        if (is_m4 && ind_n < 3) {
            fprintf(stderr, "Error: M4 indicator needs at least 3 letters (got %d)\n", ind_n);
            return 1;
        }
        if (!is_m4 && ind_n < 6) {
            fprintf(stderr, "Error: M3 indicator needs at least 6 letters (got %d)\n", ind_n);
            return 1;
        }
    }

    /* If indicator is provided, strip it from the ciphertext */
    if (ind_n > 0 && ind_n <= ct_n) {
        if (!json_mode) {
            printf("Stripping %d indicator letters from ciphertext\n", ind_n);
            printf("Indicator: %.*s\n", ind_n, indicator);
            printf("Remaining ciphertext: %d chars\n\n", ct_n - ind_n);
        }
        memmove(ct, ct + ind_n, ct_n - ind_n);
        ct_n -= ind_n;
        ct[ct_n] = '\0';
    }

    /* Self-test mode (no --ct or --stdin) */
    if (ct_n < 0) {
        if (json_mode) {
            fprintf(stderr, "Error: --format json requires --ct or --stdin\n");
            return 1;
        }

        printf("================================================================\n");
        printf("  ENIGMA CRACKER — C Implementation (M3 + M4)\n");
        printf("================================================================\n\n");

        /* ── 1. Verify simulator: decrypt U-264 with known M4 settings ── */
        printf("── 1. U-264 M4 DECRYPTION (known settings) ──\n\n");

        const char *u264_ct =
            "NCZWVUSXPNYMINHZXMQXSFWXWLKJAHSHNMCOCCAKUQPMKCSMHKSEINJUSBLK"
            "IOSXCKUBHMLLXCSJUSRRDVKOHULXWCCBGVLIYXEOAHXRHKKFVDREWEZLXOBA"
            "FGYUJQUKGRTVUKAMEURBVEKSUHHVOYHABCJWMAKLFKLMYFVNRIZRVVRTKOFD"
            "ANJMOLBGFFLEOPRGTFLVRHOWOPBEKVWMUQFMPWPARMFHAGKXIIBG";
        int u264_n = (int)strlen(u264_ct);

        printf("Ciphertext (%d chars): %s\n", u264_n, u264_ct);
        printf("Settings: M4 / beta,II,IV,I / B_thin / Rings A,A,A,V / Pos VJNA\n");
        printf("Plugboard: AT BL DF GJ HM NW OP QY RZ VX\n\n");

        int plug_m4[26]; plug_init(plug_m4);
        plug_add(plug_m4, 'A'-'A','T'-'A');
        plug_add(plug_m4, 'B'-'A','L'-'A');
        plug_add(plug_m4, 'D'-'A','F'-'A');
        plug_add(plug_m4, 'G'-'A','J'-'A');
        plug_add(plug_m4, 'H'-'A','M'-'A');
        plug_add(plug_m4, 'N'-'A','W'-'A');
        plug_add(plug_m4, 'O'-'A','P'-'A');
        plug_add(plug_m4, 'Q'-'A','Y'-'A');
        plug_add(plug_m4, 'R'-'A','Z'-'A');
        plug_add(plug_m4, 'V'-'A','X'-'A');

        char u264_pt[1024];
        m4_encrypt(R_BETA, R_II, R_IV, R_I,
                   'V'-'A',
                   'J'-'A', 'N'-'A', 'A'-'A',
                   0, 0, 0, 21,
                   REF_B_THIN, plug_m4,
                   u264_ct, u264_n, u264_pt);

        printf("Decrypted: %s\n", u264_pt);
        printf("(Expected: VONVONJLOOKSJHFFTTTEINS...)\n\n");

        /* ── 2. Self-test: encrypt known German, then brute-force ── */
        printf("── 2. SELF-TEST: encrypt + brute-force crack ──\n\n");

        const char *test_pt =
            "ANXGRIGENSTANDORTXQREISXVIERXNULXACHTXGEGNERXIMXANMARSCH"
            "XMITTLERNORDLICHERWINDXWIRTSCHAFTXEINSXNULLXZWEIXDREI"
            "XVIERXFUNFXSECHSXSIEBENXACHTXNEUNXZEHNXEINSXNULLXNULL"
            "XWETTERXKALTXWINDXNORDXOSTXSTILLEXPRESSXNICHTXSCHIESSEN";
        int test_n = (int)strlen(test_pt);

        printf("Original plaintext (%d chars): %s\n", test_n, test_pt);

        int tp[26]; plug_init(tp);
        plug_add(tp, 'A'-'A','B'-'A');
        plug_add(tp, 'C'-'A','D'-'A');
        plug_add(tp, 'E'-'A','F'-'A');

        char test_ct[512];
        m3_encrypt(R_I, R_II, R_III,
                   0, 0, 0,
                   0, 0, 0,
                   REF_B, tp,
                   test_pt, test_n, test_ct);

        printf("Encrypted (I,II,III / B / AAA / AAA / AB CD EF):\n");
        printf("  %s\n\n", test_ct);
        printf("Now brute-forcing from ciphertext only (no settings provided)...\n\n");

        CrackResult r = brute_force_m3(test_ct, test_n, 0);

        printf("\n================================================================\n");
        printf("  DONE\n");
        printf("================================================================\n");
        return 0;
    }

    /* Crack mode */
    if (ct_n == 0) {
        fprintf(stderr, "Error: ciphertext is empty after sanitizing\n");
        if (json_mode) {
            printf("{\n");
            printf("  \"mode\": \"%s\",\n", is_m4 ? "M4" : "M3");
            printf("  \"success\": false,\n");
            printf("  \"error\": \"empty ciphertext\"\n");
            printf("}\n");
        }
        return 1;
    }

    if (!json_mode) {
        printf("================================================================\n");
        printf("  ENIGMA CRACKER — %s mode\n", is_m4 ? "M4" : "M3");
        printf("================================================================\n\n");
        printf("Ciphertext (%d chars): %s\n\n", ct_n, ct);
    }

    CrackResult r;
    if (baseline_arg) {
        /* Baseline search mode: parse baseline and search ±2 */
        BaselineSettings bs;
        if (!parse_baseline(baseline_arg, &bs)) {
            fprintf(stderr, "Error: failed to parse baseline settings: %s\n", baseline_arg);
            if (json_mode) {
                printf("{\n  \"mode\": \"%s\",\n  \"success\": false,\n  \"error\": \"invalid baseline\"\n}\n", is_m4 ? "M4" : "M3");
            }
            return 1;
        }
        /* Override is_m4 based on parsed baseline */
        is_m4 = bs.is_m4;
        if (!json_mode) {
            printf("================================================================\n");
            printf("  ENIGMA CRACKER — %s Baseline Search\n", is_m4 ? "M4" : "M3");
            printf("================================================================\n\n");
            printf("Ciphertext (%d chars): %s\n\n", ct_n, ct);
        }
        if (is_m4) {
            r = baseline_search_m4(ct, ct_n, &bs, json_mode);
        } else {
            r = baseline_search_m3(ct, ct_n, &bs, json_mode);
        }
    } else if (ind_n > 0) {
        /* Indicator mode: use indicator-based message key recovery */
        if (is_m4) {
            r = brute_force_m4_indicator(ct, ct_n, indicator, ind_n, json_mode);
        } else {
            r = brute_force_m3_indicator(ct, ct_n, indicator, ind_n, json_mode);
        }
    } else if (is_m4) {
        r = brute_force_m4(ct, ct_n, json_mode);
    } else {
        r = brute_force_m3(ct, ct_n, json_mode);
    }

    if (json_mode) {
        print_json_result(&r);
    }

    fprintf(stderr, "PROGRESS:done:0:0\n");
    fflush(stderr);

    return 0;
}