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
 *   - U-264 M4 ciphertext decryption (known settings verification)
 *   - Self-test: encrypt a known message, then brute-forces it from ciphertext only
 *   - CLI interface for external callers (GUI, scripts)
 *   - JSON output mode for machine parsing
 *
 * Build:  gcc -O3 -fopenmp -o enigma_cracker enigma_cracker.c -lm
 * Run:    ./enigma_cracker                              # self-test mode
 *         ./enigma_cracker --ct CIPHERTEXT --mode M3     # crack M3
 *         ./enigma_cracker --ct CIPHERTEXT --mode M4     # crack M4
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

enum { R_I=0, R_II, R_III, R_IV, R_V, R_VI, R_VII, R_R8, R_BETA, R_GAMMA };
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

/* German trigram + common-word score */
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
    int best_gs = german_score(best_out, n);

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
                int gs = german_score(tmp, n);
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
                int gs = german_score(tmp, n);
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
                int gs = german_score(tmp, n);
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
        int gs = german_score(tmp, n);
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
    return german_score(best_out, n);
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
    int best_gs = german_score(best_out, n);

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
                int gs = german_score(tmp, n);
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
                int gs = german_score(tmp, n);
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
                int gs = german_score(tmp, n);
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
        int gs = german_score(tmp, n);
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
    return german_score(best_out, n);
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

    /* Rotors to search: I–V (5 rotors → 60 permutations) */
    int sr[5] = {R_I, R_II, R_III, R_IV, R_V};
    int sref[2] = {REF_B, REF_C};
    int idplug[26]; plug_init(idplug);

    /* IC threshold ≈ 0.050 × n × (n−1) */
    int thresh = (int)(0.050 * (double)n * (n - 1));

    Cand cand[MAX_CAND];
    int ncand = 0;
    int min_ic = 0;

    long long total = 60LL * 2 * 26*26*26;
    if (!json_mode)
        printf("Phase 1: %lld configs (60 rotor perms × 2 reflectors × 26³ positions, rings=AAA)\n", total);
    fprintf(stderr, "PROGRESS:phase1:0:%lld\n", total);
    fflush(stderr);

    double t0 = now_sec();
    long long cnt = 0;

    #pragma omp parallel for collapse(2) schedule(dynamic) reduction(+:cnt) shared(cand, ncand, min_ic)
    for (int ai = 0; ai < 5; ai++)
    for (int aj = 0; aj < 5; aj++) {
        if (aj == ai) continue;
        for (int ak = 0; ak < 5; ak++) {
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
        int best_ic = cand[c].ic;
        int bg0 = 0, bg1 = 0, bg2 = 0;

        for (int g0 = 0; g0 < 26; g0++)
        for (int g1 = 0; g1 < 26; g1++)
        for (int g2 = 0; g2 < 26; g2++) {
            int ic = fast_ic_m3(r0,r1,r2, p0,p1,p2, g0,g1,g2, rf, idplug, ct, n);
            if (ic > best_ic) {
                best_ic = ic;
                bg0 = g0; bg1 = g1; bg2 = g2;
            }
        }
        cand[c].ic = best_ic;
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

    int sr[5] = {R_I, R_II, R_III, R_IV, R_V};
    int sref[2] = {REF_B_THIN, REF_C_THIN};
    int thin_rotors[2] = {R_BETA, R_GAMMA};
    int idplug[26]; plug_init(idplug);

    int thresh = (int)(0.050 * (double)n * (n - 1));

    /* Total: 2 thin × 26 thin_pos × 60 rotor_perms × 2 ref × 26³ positions */
    long long total = 2LL * 26 * 60 * 2 * 26*26*26;
    if (!json_mode) {
        printf("M4 Brute-force: %lld configs (2 thin × 26 thin_pos × 60 rotor perms × 2 ref × 26³ pos)\n", total);
        printf("Phase 1: Searching rotor permutations and positions (rings=AAA)...\n");
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
        for (int ai = 0; ai < 5; ai++)
        for (int aj = 0; aj < 5; aj++) {
            if (aj == ai) continue;
            for (int ak = 0; ak < 5; ak++) {
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
    /* Search all 26^3 ring settings for every candidate (thin ring stays at 0). */
    int top_rings = ncand;
    if (!json_mode)
        printf("Phase 2: Ring search on all %d candidates (26³ = 17,576 rings each)...\n", top_rings);
    fprintf(stderr, "PROGRESS:phase2:0:%d\n", top_rings);
    fflush(stderr);

    for (int c = 0; c < top_rings; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        int thin = cand[c].thin;
        int tp = cand[c].tp;
        int best_ic = cand[c].ic;
        int bg0 = 0, bg1 = 0, bg2 = 0;

        /* Search all 26^3 ring settings (thin ring tg=0) */
        for (int g0 = 0; g0 < 26; g0++)
        for (int g1 = 0; g1 < 26; g1++)
        for (int g2 = 0; g2 < 26; g2++) {
            int ic = fast_ic_m4(thin, r0,r1,r2, tp,p0,p1,p2, 0,g0,g1,g2, rf, idplug, ct, n);
            if (ic > best_ic) {
                best_ic = ic;
                bg0 = g0; bg1 = g1; bg2 = g2;
            }
        }

        cand[c].ic = best_ic;
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
    int bThin=R_BETA, bR0=0,bR1=0,bR2=0,bRef=0,bP0=0,bP1=0,bP2=0,bTp=0;
    int bG0=0,bG1=0,bG2=0;

    for (int c = 0; c < top_hc; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        int thin = cand[c].thin;
        int tp = cand[c].tp;
        /* Use the best ring settings found in Phase 2 */
        int bg0 = cand[c].g0, bg1 = cand[c].g1, bg2 = cand[c].g2;

        int plug[26];
        char out[512];

        /* Hill climb with the best ring settings from Phase 2 */
        int gs = hill_climb_m4(thin, r0,r1,r2, tp,p0,p1,p2, 0,bg0,bg1,bg2, rf, ct, n, plug, out);

        memcpy(best_plug, plug, sizeof(plug));
        strcpy(best_text, out);

        if (!json_mode) {
            printf("  #%d  Thin %s  Rotors %s,%s,%s  Ref %s  ThinPos %c  Pos %c%c%c  Rings %c%c%c\n",
                   c+1,
                   ROTOR_NAME[thin],
                   ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2],
                   REFLECTOR_NAME[rf],
                   tp+'A',
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
            bThin = thin;
            bR0=r0; bR1=r1; bR2=r2; bRef=rf;
            bTp=tp; bP0=p0; bP1=p1; bP2=p2;
            bG0=bg0; bG1=bg1; bG2=bg2;
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
    result.tg = 0;
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
        printf("  \"thin_ring\": \"A\",\n");
    }

    printf("  \"rotors\": \"%s, %s, %s\",\n",
           ROTOR_NAME[r->r0], ROTOR_NAME[r->r1], ROTOR_NAME[r->r2]);
    printf("  \"reflector\": \"%s\",\n", REFLECTOR_NAME[r->ref]);
    printf("  \"positions\": \"%c%c%c\",\n",
           r->p0+'A', r->p1+'A', r->p2+'A');

    if (r->is_m4)
        printf("  \"rings\": \"%c%c%c\",\n", r->g0+'A', r->g1+'A', r->g2+'A');
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
        "  --format text|json Output format (default: text)\n"
        "  --help             Show this help\n"
        "\n"
        "If no --ct or --stdin is given, runs self-test mode.\n"
        "\n"
        "Examples:\n"
        "  %s --ct NCZWVUSXPNYMINHZXMQXSFWXWLKJAHSHNMCOCCAKUQPMKCSMHKSEINJUSBLK --mode M4\n"
        "  echo NCZWVUSXPNYMINHZXMQXSFWXWLKJAHSHNMCOCCAKUQPMKCSMHKSEINJUSBLK | %s --stdin --mode M4 --format json\n",
        prog, prog, prog);
}

int main(int argc, char *argv[])
{
    init_tables();

    /* Parse arguments */
    const char *ct_arg = NULL;
    int use_stdin = 0;
    const char *mode_str = "M3";
    const char *format_str = "text";
    int json_mode = 0;
    int is_m4 = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ct") == 0 && i + 1 < argc) {
            ct_arg = argv[++i];
        } else if (strcmp(argv[i], "--stdin") == 0) {
            use_stdin = 1;
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode_str = argv[++i];
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
    if (is_m4) {
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