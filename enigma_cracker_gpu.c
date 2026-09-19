/*
 * enigma_cracker_gpu.c — Enigma M3/M4 cracker with OpenCL GPU acceleration
 *
 * Architecture:
 *   GPU (OpenCL):  Phase 1 — brute-force all rotor perms × positions, IC scoring
 *   CPU:           Phase 2 — ring search on top candidates
 *   CPU:           Phase 3 — plugboard hill climbing on top 10 candidates
 *
 * Falls back to pure CPU (OpenMP) if no OpenCL device is available.
 *
 * Build:  gcc -O3 -fopenmp -o enigma_cracker_gpu enigma_cracker_gpu.c -lm -lOpenCL
 * Run:    ./enigma_cracker_gpu                              # self-test mode
 *         ./enigma_cracker_gpu --ct CIPHERTEXT --mode M3     # crack M3
 *         ./enigma_cracker_gpu --ct CIPHERTEXT --mode M4     # crack M4
 *         ./enigma_cracker_gpu --ct CIPHERTEXT --mode M3 --format json
 *         ./enigma_cracker_gpu --cpu                         # force CPU fallback
 *         echo CIPHERTEXT | ./enigma_cracker_gpu --stdin --mode M4
 *
 * The OpenCL kernel (enigma_kernel.cl) is loaded at runtime.  If the kernel
 * file is not found or OpenCL is unavailable, the program automatically
 * falls back to the CPU code path.
 */

#ifdef __APPLE__
#include <OpenCL/cl.h>
#else
#include <CL/cl.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#ifdef _OPENMP
#include <omp.h>
#endif
#ifndef _WIN32
#include <unistd.h>  /* readlink */
#endif

#include "german_words_embedded.h"  /* Embedded German word list fallback */

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
/*  Executable directory (for finding enigma_kernel.cl)        */
/* ────────────────────────────────────────────────────────── */

/* Returns the directory containing the running executable.
 * On Windows uses GetModuleFileName; on Linux reads /proc/self/exe.
 * Returns NULL on failure.  Caller must not free the returned pointer
 * (it points to a static buffer). */
static const char *exe_dir(void)
{
    static char buf[1024];
#ifdef _WIN32
    DWORD len = GetModuleFileNameA(NULL, buf, sizeof(buf));
    if (len == 0 || len >= sizeof(buf)) return NULL;
#else
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len < 0) return NULL;
    buf[len] = '\0';
#endif
    /* Strip the filename, keep only the directory */
    char *slash = strrchr(buf, '/');
    char *bslash = strrchr(buf, '\\');
    char *last = (bslash > slash) ? bslash : slash;
    if (last) {
        last[1] = '\0';
    } else {
        buf[0] = '\0';
    }
    return buf;
}

/* ────────────────────────────────────────────────────────── */
/*  Rotor and reflector data (identical to enigma_cracker.c)   */
/* ────────────────────────────────────────────────────────── */

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

static int rfwd[10][26];
static int rbwd[10][26];
static int rnotch[10][26];
static int refw[4][26];

static int tri_score[26][26][26];

/* ────────────────────────────────────────────────────────── */
/*  German dictionary hash set                                  */
/* ────────────────────────────────────────────────────────── */

#define DICT_HASH_SIZE 262144
#define DICT_MAX_WORD   32

static char  *dict_slots[DICT_HASH_SIZE];
static int    dict_count = 0;
static int    dict_loaded = 0;

static unsigned dict_hash(const char *word, int len)
{
    unsigned h = 2166136261u;
    for (int i = 0; i < len; i++) {
        h ^= (unsigned char)word[i];
        h *= 16777619u;
    }
    return h & (DICT_HASH_SIZE - 1);
}

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
            return;
    }
}

static int dict_contains(const char *word, int len)
{
    if (len < 3 || len >= DICT_MAX_WORD) return 0;
    unsigned h = dict_hash(word, len);
    for (int i = 0; i < DICT_HASH_SIZE; i++) {
        unsigned idx = (h + i) & (DICT_HASH_SIZE - 1);
        if (!dict_slots[idx])
            return 0;
        if ((int)strlen(dict_slots[idx]) == len &&
            strncmp(dict_slots[idx], word, len) == 0)
            return 1;
    }
    return 0;
}

static int load_german_dictionary(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[DICT_MAX_WORD];
    while (fgets(line, sizeof(line), f)) {
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

static void load_dictionary_auto(void)
{
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

/* ────────────────────────────────────────────────────────── */
/*  Enigma simulation (CPU — reused for Phase 2/3)             */
/* ────────────────────────────────────────────────────────── */

static inline int m26(int x)
{
    if (x < 0)   return x + 26;
    if (x >= 26) return x - 26;
    return x;
}

static void plug_init(int *p) { for (int i = 0; i < 26; i++) p[i] = i; }
static void plug_add(int *p, int a, int b) { p[a] = b; p[b] = a; }

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
        out[i] = c + 'A';
    }
    out[n] = '\0';
}

static void m4_encrypt(
    int thin, int r0, int r1, int r2,
    int tp, int p0, int p1, int p2,
    int tg, int g0, int g1, int g2,
    int ref, const int *plug,
    const char *ct, int n, char *out)
{
    int pos0 = p0, pos1 = p1, pos2 = p2;
    int to = tp - tg;
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
        out[i] = c + 'A';
    }
    out[n] = '\0';
}

/* ────────────────────────────────────────────────────────── */
/*  Fitness functions (CPU — reused for Phase 2/3)             */
/* ────────────────────────────────────────────────────────── */

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

static int german_score(const char *t, int n)
{
    int s = 0;
    for (int i = 0; i < n - 2; i++)
        s += tri_score[t[i]-'A'][t[i+1]-'A'][t[i+2]-'A'];
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

static int german_word_score(const char *t, int n)
{
    if (!dict_loaded || dict_count == 0)
        return german_score(t, n);
    int score = 0;
    int i = 0;
    while (i < n) {
        if (t[i] < 'A' || t[i] > 'Z') { i++; continue; }
        if (t[i] == 'X') { i++; continue; }
        int start = i;
        while (i < n && t[i] >= 'A' && t[i] <= 'Z' && t[i] != 'X')
            i++;
        int seglen = i - start;
        int pos = 0;
        while (pos < seglen) {
            int found = 0;
            int maxlen = seglen - pos;
            if (maxlen >= DICT_MAX_WORD) maxlen = DICT_MAX_WORD - 1;
            for (int wlen = maxlen; wlen >= 3; wlen--) {
                if (dict_contains(&t[start + pos], wlen)) {
                    score += wlen * wlen;
                    pos += wlen;
                    found = 1;
                    break;
                }
            }
            if (!found) pos++;
        }
    }
    return score;
}

static int german_fitness(const char *t, int n)
{
    if (dict_loaded && dict_count > 0)
        return german_word_score(t, n) + german_score(t, n);
    return german_score(t, n);
}

/* ────────────────────────────────────────────────────────── */
/*  Fast IC functions (CPU fallback for Phase 1)              */
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
/*  Hill climbing (CPU — Phase 3)                               */
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
    double best_fit = ic_num(best_out, n) * 100.0 + best_gs;

    for (int iter = 0; iter < 13; iter++) {
        int best_a = -1, best_b = -1;
        double best_new = best_fit;
        for (int a = 0; a < 26; a++) {
            if (used[a]) continue;
            for (int b = a + 1; b < 26; b++) {
                if (used[b]) continue;
                best_plug[a] = b; best_plug[b] = a;
                char tmp[512];
                m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref, best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;
                if (fit > best_new) { best_new = fit; best_a = a; best_b = b; }
                best_plug[a] = a; best_plug[b] = b;
            }
        }
        if (best_a < 0) break;
        best_plug[best_a] = best_b; best_plug[best_b] = best_a;
        used[best_a] = 1; used[best_b] = 1;
        best_fit = best_new;
    }

    for (int round = 0; round < 3; round++) {
        int improved = 0;
        for (int a = 0; a < 26; a++) {
            if (!used[a]) continue;
            int b = best_plug[a];
            for (int c = 0; c < 26; c++) {
                if (used[c] || c == b) continue;
                best_plug[a] = a; best_plug[b] = b;
                best_plug[c] = b; best_plug[b] = c;
                char tmp[512];
                m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref, best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;
                if (fit > best_fit) {
                    best_fit = fit; used[a] = 0; used[c] = 1; improved = 1;
                } else {
                    best_plug[c] = c; best_plug[b] = a; best_plug[a] = b;
                }
            }
            for (int c = 0; c < 26; c++) {
                if (used[c] || c == a) continue;
                best_plug[b] = b; best_plug[a] = a;
                best_plug[c] = a; best_plug[a] = c;
                char tmp[512];
                m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref, best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;
                if (fit > best_fit) {
                    best_fit = fit; used[b] = 0; used[c] = 1; improved = 1;
                } else {
                    best_plug[c] = c; best_plug[a] = b; best_plug[b] = a;
                }
            }
        }
        if (!improved) break;
    }

    for (int a = 0; a < 26; a++) {
        if (!used[a]) continue;
        int b = best_plug[a];
        best_plug[a] = a; best_plug[b] = b;
        char tmp[512];
        m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref, best_plug, ct, n, tmp);
        int gs = german_fitness(tmp, n);
        double fit = ic_num(tmp, n) * 100.0 + gs;
        if (fit > best_fit) { best_fit = fit; used[a] = 0; used[b] = 0; }
        else { best_plug[a] = b; best_plug[b] = a; }
    }

    m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, ref, best_plug, ct, n, best_out);
    return german_fitness(best_out, n);
}

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
                best_plug[a] = b; best_plug[b] = a;
                char tmp[512];
                m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref, best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;
                if (fit > best_new) { best_new = fit; best_a = a; best_b = b; }
                best_plug[a] = a; best_plug[b] = b;
            }
        }
        if (best_a < 0) break;
        best_plug[best_a] = best_b; best_plug[best_b] = best_a;
        used[best_a] = 1; used[best_b] = 1;
        best_fit = best_new;
    }

    for (int round = 0; round < 3; round++) {
        int improved = 0;
        for (int a = 0; a < 26; a++) {
            if (!used[a]) continue;
            int b = best_plug[a];
            for (int c = 0; c < 26; c++) {
                if (used[c] || c == b) continue;
                best_plug[a] = a; best_plug[b] = b;
                best_plug[c] = b; best_plug[b] = c;
                char tmp[512];
                m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref, best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;
                if (fit > best_fit) {
                    best_fit = fit; used[a] = 0; used[c] = 1; improved = 1;
                } else {
                    best_plug[c] = c; best_plug[b] = a; best_plug[a] = b;
                }
            }
            for (int c = 0; c < 26; c++) {
                if (used[c] || c == a) continue;
                best_plug[b] = b; best_plug[a] = a;
                best_plug[c] = a; best_plug[a] = c;
                char tmp[512];
                m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref, best_plug, ct, n, tmp);
                int gs = german_fitness(tmp, n);
                double fit = ic_num(tmp, n) * 100.0 + gs;
                if (fit > best_fit) {
                    best_fit = fit; used[b] = 0; used[c] = 1; improved = 1;
                } else {
                    best_plug[c] = c; best_plug[a] = b; best_plug[b] = a;
                }
            }
        }
        if (!improved) break;
    }

    for (int a = 0; a < 26; a++) {
        if (!used[a]) continue;
        int b = best_plug[a];
        best_plug[a] = a; best_plug[b] = b;
        char tmp[512];
        m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref, best_plug, ct, n, tmp);
        int gs = german_fitness(tmp, n);
        double fit = ic_num(tmp, n) * 100.0 + gs;
        if (fit > best_fit) { best_fit = fit; used[a] = 0; used[b] = 0; }
        else { best_plug[a] = b; best_plug[b] = a; }
    }

    m4_encrypt(thin,r0,r1,r2, tp,p0,p1,p2, tg,g0,g1,g2, ref, best_plug, ct, n, best_out);
    return german_fitness(best_out, n);
}

/* ────────────────────────────────────────────────────────── */
/*  Crack result + candidate structures                         */
/* ────────────────────────────────────────────────────────── */

typedef struct {
    int r0, r1, r2;
    int thin;
    int ref;
    int p0, p1, p2;
    int tp;
    int g0, g1, g2;
    int tg;
    int plug[26];
    char text[512];
    int german_score;
    double elapsed;
    long long configs;
    int is_m4;
} CrackResult;

#define MAX_CAND 500
#define CAND_FIELDS 13

typedef struct {
    int ic;
    int r0, r1, r2;
    int ref;
    int p0, p1, p2;
    int g0, g1, g2;
    int thin;
    int tp;
} Cand;

static int cand_cmp(const void *a, const void *b)
{
    return ((const Cand *)b)->ic - ((const Cand *)a)->ic;
}

/* ────────────────────────────────────────────────────────── */
/*  Rotor permutation generation                                */
/* ────────────────────────────────────────────────────────── */

static int gen_perms(int *perms, int rotors[8], int n_rotors)
{
    int idx = 0;
    for (int i = 0; i < n_rotors; i++)
    for (int j = 0; j < n_rotors; j++) {
        if (j == i) continue;
        for (int k = 0; k < n_rotors; k++) {
            if (k == i || k == j) continue;
            perms[idx*3]   = rotors[i];
            perms[idx*3+1] = rotors[j];
            perms[idx*3+2] = rotors[k];
            idx++;
        }
    }
    return idx;  /* number of permutations */
}

/* ────────────────────────────────────────────────────────── */
/*  OpenCL helpers                                              */
/* ────────────────────────────────────────────────────────── */

#define CL_CHECK(err, msg) \
    do { if ((err) != CL_SUCCESS) { \
        fprintf(stderr, "OpenCL error %d: %s\n", err, msg); \
        return 0; \
    } } while (0)

static int ocl_available(void)
{
    cl_uint num_platforms = 0;
    cl_int err = clGetPlatformIDs(0, NULL, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) return 0;
    cl_uint num_devices = 0;
    err = clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, 0, NULL, &num_devices);
    if (err != CL_SUCCESS || num_devices == 0) return 0;
    return 1;
}

static char *load_kernel_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/* Run Phase 1 on GPU via OpenCL.  Returns number of candidates, or -1 on error. */
static int gpu_phase1(
    int is_m4,
    const char *ct_chars, int n,
    int threshold,
    Cand *cand_out,
    long long *config_count,
    int json_mode,
    const char *kernel_path)  /* explicit --kernel path, or NULL */
{
    cl_int err;
    cl_platform_id platform;
    cl_device_id device;
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_mem mem_rfwd, mem_rbwd, mem_rnotch, mem_refw;
    cl_mem mem_perms, mem_ct, mem_cand_count, mem_cand_out;

    /* Flatten rotor tables into 1D arrays for GPU */
    int rfwd_flat[10*26], rbwd_flat[10*26], rnotch_flat[10*26], refw_flat[4*26];
    for (int r = 0; r < 10; r++)
        for (int i = 0; i < 26; i++) {
            rfwd_flat[r*26+i] = rfwd[r][i];
            rbwd_flat[r*26+i] = rbwd[r][i];
            rnotch_flat[r*26+i] = rnotch[r][i];
        }
    for (int r = 0; r < 4; r++)
        for (int i = 0; i < 26; i++)
            refw_flat[r*26+i] = refw[r][i];

    /* Ciphertext as ints */
    int *ct_ints = (int *)malloc(n * sizeof(int));
    if (!ct_ints) return -1;
    for (int i = 0; i < n; i++) ct_ints[i] = ct_chars[i] - 'A';

    /* Rotor permutations */
    int sr[8] = {R_I, R_II, R_III, R_IV, R_V, R_VI, R_VII, R_VIII};
    int *perms = (int *)malloc(336 * 3 * sizeof(int));
    if (!perms) { free(ct_ints); return -1; }
    int n_perms = gen_perms(perms, sr, 8);
    (void)n_perms; /* should be 336 */

    /* Load kernel source — search in order:
     *   1. Explicit --kernel path (from GUI / PyInstaller)
     *   2. Executable's directory (GetModuleFileName / /proc/self/exe)
     *   3. Current directory / ./enigma_kernel.cl
     */
    const char *kernel_paths[8];
    int n_paths = 0;
    char exe_kernel[1024];

    if (kernel_path)
        kernel_paths[n_paths++] = kernel_path;

    /* Build "<exe_dir>/enigma_kernel.cl" */
    const char *ed = exe_dir();
    if (ed && ed[0]) {
        snprintf(exe_kernel, sizeof(exe_kernel), "%senigma_kernel.cl", ed);
        kernel_paths[n_paths++] = exe_kernel;
    }

    kernel_paths[n_paths++] = "enigma_kernel.cl";
    kernel_paths[n_paths++] = "./enigma_kernel.cl";
    kernel_paths[n_paths] = NULL;

    char *kernel_src = NULL;
    for (int i = 0; i < n_paths; i++) {
        kernel_src = load_kernel_file(kernel_paths[i]);
        if (kernel_src) {
            if (!json_mode)
                fprintf(stderr, "Loaded kernel from %s\n", kernel_paths[i]);
            break;
        }
    }
    if (!kernel_src) {
        fprintf(stderr, "Warning: enigma_kernel.cl not found, cannot use GPU\n");
        free(ct_ints); free(perms);
        return -1;
    }

    /* ── Setup OpenCL ── */
    err = clGetPlatformIDs(1, &platform, NULL);
    CL_CHECK(err, "clGetPlatformIDs");

    /* Prefer GPU, fall back to any device */
    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
    if (err != CL_SUCCESS) {
        err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, NULL);
        CL_CHECK(err, "clGetDeviceIDs (fallback)");
    }

    /* Print device name */
    {
        char dev_name[256] = {0};
        clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(dev_name), dev_name, NULL);
        fprintf(stderr, "Using OpenCL device: %s\n", dev_name);
    }

    context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    CL_CHECK(err, "clCreateContext");

#ifdef CL_VERSION_2_0
    queue = clCreateCommandQueueWithProperties(context, device, NULL, &err);
#else
    queue = clCreateCommandQueue(context, device, 0, &err);
#endif
    CL_CHECK(err, "clCreateCommandQueue");

    /* ── Build program ── */
    const char *src_str = kernel_src;
    size_t src_len = strlen(kernel_src);
    program = clCreateProgramWithSource(context, 1, &src_str, &src_len, &err);
    CL_CHECK(err, "clCreateProgramWithSource");

    err = clBuildProgram(program, 1, &device, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t log_size = 0;
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
        char *log = (char *)malloc(log_size + 1);
        if (log) {
            clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
            log[log_size] = '\0';
            fprintf(stderr, "OpenCL build error:\n%s\n", log);
            free(log);
        }
        clReleaseProgram(program);
        clReleaseCommandQueue(queue);
        clReleaseContext(context);
        free(kernel_src); free(ct_ints); free(perms);
        return -1;
    }

    /* Select kernel */
    const char *kernel_name = is_m4 ? "enigma_m4_ic" : "enigma_m3_ic";
    kernel = clCreateKernel(program, kernel_name, &err);
    CL_CHECK(err, "clCreateKernel");

    /* ── Create buffers ── */
    mem_rfwd = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                              10*26*sizeof(int), rfwd_flat, &err);
    CL_CHECK(err, "mem_rfwd");
    mem_rbwd = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                              10*26*sizeof(int), rbwd_flat, &err);
    CL_CHECK(err, "mem_rbwd");
    mem_rnotch = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                10*26*sizeof(int), rnotch_flat, &err);
    CL_CHECK(err, "mem_rnotch");
    mem_refw = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                             4*26*sizeof(int), refw_flat, &err);
    CL_CHECK(err, "mem_refw");
    mem_perms = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                               336*3*sizeof(int), perms, &err);
    CL_CHECK(err, "mem_perms");
    mem_ct = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                            n*sizeof(int), ct_ints, &err);
    CL_CHECK(err, "mem_ct");

    /* Candidate output buffer */
    int max_cand_gpu = MAX_CAND * 2;  /* allow some slack */
    int *cand_buf = (int *)calloc(max_cand_gpu * CAND_FIELDS, sizeof(int));
    int *cand_count_buf = (int *)calloc(1, sizeof(int));
    if (!cand_buf || !cand_count_buf) {
        fprintf(stderr, "Memory allocation failed for GPU candidate buffers\n");
        clReleaseMemObject(mem_rfwd); clReleaseMemObject(mem_rbwd);
        clReleaseMemObject(mem_rnotch); clReleaseMemObject(mem_refw);
        clReleaseMemObject(mem_perms); clReleaseMemObject(mem_ct);
        clReleaseKernel(kernel); clReleaseProgram(program);
        clReleaseCommandQueue(queue); clReleaseContext(context);
        free(kernel_src); free(ct_ints); free(perms);
        free(cand_buf); free(cand_count_buf);
        return -1;
    }

    mem_cand_out = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                                  max_cand_gpu * CAND_FIELDS * sizeof(int), cand_buf, &err);
    CL_CHECK(err, "mem_cand_out");
    mem_cand_count = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                                    sizeof(int), cand_count_buf, &err);
    CL_CHECK(err, "mem_cand_count");

    /* ── Set kernel arguments ── */
    int ref_base = is_m4 ? REF_B_THIN : REF_B;
    int n_perms_int = 336;
    long long total_configs = 0;

    /* Work size: 336 perms × 2 refs × 26³ positions = 11,803,392 */
    size_t global_size = 336LL * 2 * 26 * 26 * 26;

    double t0 = now_sec();

    if (!is_m4) {
        /* M3: single kernel dispatch */
        int arg = 0;
        err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_rfwd);     CL_CHECK(err, "arg rfwd");
        err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_rbwd);     CL_CHECK(err, "arg rbwd");
        err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_rnotch);   CL_CHECK(err, "arg rnotch");
        err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_refw);     CL_CHECK(err, "arg refw");
        err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_perms);    CL_CHECK(err, "arg perms");
        err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_ct);       CL_CHECK(err, "arg ct");
        err = clSetKernelArg(kernel, arg++, sizeof(int), &n);               CL_CHECK(err, "arg n");
        err = clSetKernelArg(kernel, arg++, sizeof(int), &threshold);        CL_CHECK(err, "arg threshold");
        err = clSetKernelArg(kernel, arg++, sizeof(int), &ref_base);        CL_CHECK(err, "arg ref_base");
        err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_cand_count); CL_CHECK(err, "arg cand_count");
        err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_cand_out);  CL_CHECK(err, "arg cand_out");
        err = clSetKernelArg(kernel, arg++, sizeof(int), &max_cand_gpu);    CL_CHECK(err, "arg max_cand");

        err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_size, NULL, 0, NULL, NULL);
        CL_CHECK(err, "clEnqueueNDRangeKernel (M3)");

        total_configs = 336LL * 2 * 26 * 26 * 26;
    } else {
        /* M4: dispatch one kernel per (thin, thin_pos) combination */
        int thin_rotors[2] = {R_BETA, R_GAMMA};
        for (int thi = 0; thi < 2; thi++) {
            for (int tp = 0; tp < 26; tp++) {
                /* Reset counter for each batch to avoid overflow */
                int zero = 0;
                clEnqueueWriteBuffer(queue, mem_cand_count, CL_TRUE, 0, sizeof(int), &zero, 0, NULL, NULL);

                int arg = 0;
                err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_rfwd);     CL_CHECK(err, "arg rfwd");
                err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_rbwd);     CL_CHECK(err, "arg rbwd");
                err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_rnotch);   CL_CHECK(err, "arg rnotch");
                err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_refw);     CL_CHECK(err, "arg refw");
                err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_perms);    CL_CHECK(err, "arg perms");
                err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_ct);       CL_CHECK(err, "arg ct");
                err = clSetKernelArg(kernel, arg++, sizeof(int), &n);               CL_CHECK(err, "arg n");
                err = clSetKernelArg(kernel, arg++, sizeof(int), &threshold);        CL_CHECK(err, "arg threshold");
                err = clSetKernelArg(kernel, arg++, sizeof(int), &ref_base);        CL_CHECK(err, "arg ref_base");
                err = clSetKernelArg(kernel, arg++, sizeof(int), &thin_rotors[thi]); CL_CHECK(err, "arg thin");
                err = clSetKernelArg(kernel, arg++, sizeof(int), &tp);               CL_CHECK(err, "arg tp");
                err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_cand_count); CL_CHECK(err, "arg cand_count");
                err = clSetKernelArg(kernel, arg++, sizeof(cl_mem), &mem_cand_out);  CL_CHECK(err, "arg cand_out");
                err = clSetKernelArg(kernel, arg++, sizeof(int), &max_cand_gpu);    CL_CHECK(err, "arg max_cand");

                err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_size, NULL, 0, NULL, NULL);
                CL_CHECK(err, "clEnqueueNDRangeKernel (M4)");

                /* Read back candidates for this batch and merge */
                clFinish(queue);
                int batch_count = 0;
                clEnqueueReadBuffer(queue, mem_cand_count, CL_TRUE, 0, sizeof(int), &batch_count, 0, NULL, NULL);
                if (batch_count > 0) {
                    clEnqueueReadBuffer(queue, mem_cand_out, CL_TRUE, 0,
                                        batch_count * CAND_FIELDS * sizeof(int),
                                        cand_buf, 0, NULL, NULL);
                }

                /* Merge batch into cand_out array */
                for (int b = 0; b < batch_count && *config_count < MAX_CAND; b++) {
                    int base = b * CAND_FIELDS;
                    Cand *c = &cand_out[*config_count];
                    c->ic   = cand_buf[base + 0];
                    c->r0   = cand_buf[base + 1];
                    c->r1   = cand_buf[base + 2];
                    c->r2   = cand_buf[base + 3];
                    c->ref  = cand_buf[base + 4];
                    c->p0   = cand_buf[base + 5];
                    c->p1   = cand_buf[base + 6];
                    c->p2   = cand_buf[base + 7];
                    c->g0   = cand_buf[base + 8];
                    c->g1   = cand_buf[base + 9];
                    c->g2   = cand_buf[base + 10];
                    c->thin = cand_buf[base + 11];
                    c->tp   = cand_buf[base + 12];
                    (*config_count)++;
                }

                if (!json_mode) {
                    fprintf(stderr, "\r  M4 batch %d/52 (thin=%s tp=%c): %d candidates so far",
                            thi*26 + tp + 1, ROTOR_NAME[thin_rotors[thi]], tp+'A', (int)*config_count);
                }
            }
        }
        if (!json_mode) fprintf(stderr, "\n");
        total_configs = 2LL * 26 * 336 * 2 * 26 * 26 * 26;
    }

    clFinish(queue);
    double t1 = now_sec();

    if (!is_m4) {
        /* Read back candidates for M3 (single dispatch) */
        int gpu_count = 0;
        clEnqueueReadBuffer(queue, mem_cand_count, CL_TRUE, 0, sizeof(int), &gpu_count, 0, NULL, NULL);
        if (gpu_count > max_cand_gpu) gpu_count = max_cand_gpu;

        if (gpu_count > 0) {
            clEnqueueReadBuffer(queue, mem_cand_out, CL_TRUE, 0,
                                gpu_count * CAND_FIELDS * sizeof(int),
                                cand_buf, 0, NULL, NULL);
        }

        for (int b = 0; b < gpu_count && *config_count < MAX_CAND; b++) {
            int base = b * CAND_FIELDS;
            Cand *c = &cand_out[*config_count];
            c->ic   = cand_buf[base + 0];
            c->r0   = cand_buf[base + 1];
            c->r1   = cand_buf[base + 2];
            c->r2   = cand_buf[base + 3];
            c->ref  = cand_buf[base + 4];
            c->p0   = cand_buf[base + 5];
            c->p1   = cand_buf[base + 6];
            c->p2   = cand_buf[base + 7];
            c->g0   = cand_buf[base + 8];
            c->g1   = cand_buf[base + 9];
            c->g2   = cand_buf[base + 10];
            c->thin = cand_buf[base + 11];
            c->tp   = cand_buf[base + 12];
            (*config_count)++;
        }
    }

    if (!json_mode) {
        printf("  GPU Phase 1: %lld configs in %.2fs (%.0f/s)\n",
               total_configs, t1-t0, total_configs/(t1-t0));
        printf("  Candidates above IC threshold: %d\n\n", (int)*config_count);
    }
    fprintf(stderr, "PROGRESS:phase1:done:%lld\n", total_configs);
    fflush(stderr);

    /* Cleanup */
    clReleaseMemObject(mem_rfwd);
    clReleaseMemObject(mem_rbwd);
    clReleaseMemObject(mem_rnotch);
    clReleaseMemObject(mem_refw);
    clReleaseMemObject(mem_perms);
    clReleaseMemObject(mem_ct);
    clReleaseMemObject(mem_cand_count);
    clReleaseMemObject(mem_cand_out);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(context);
    free(kernel_src);
    free(ct_ints);
    free(perms);
    free(cand_buf);
    free(cand_count_buf);

    return (int)*config_count;
}

/* ────────────────────────────────────────────────────────── */
/*  CPU Phase 1 fallback (OpenMP)                               */
/* ────────────────────────────────────────────────────────── */

static int cpu_phase1_m3(const char *ct, int n, int threshold, Cand *cand, int json_mode)
{
    int sr[8] = {R_I, R_II, R_III, R_IV, R_V, R_VI, R_VII, R_VIII};
    int sref[2] = {REF_B, REF_C};
    int idplug[26]; plug_init(idplug);

    Cand local_cand[MAX_CAND];
    int ncand = 0;
    int min_ic = 0;

    long long total = 336LL * 2 * 26*26*26;
    if (!json_mode)
        printf("Phase 1 (CPU): %lld configs (336 rotor perms × 2 reflectors × 26³ positions, rings=AAA)\n", total);
    fprintf(stderr, "PROGRESS:phase1:0:%lld\n", total);
    fflush(stderr);

    double t0 = now_sec();
    long long cnt = 0;

    #pragma omp parallel for collapse(2) schedule(dynamic) reduction(+:cnt) shared(local_cand, ncand, min_ic)
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
                if (ic > threshold) {
                    #pragma omp critical(cand_m3)
                    {
                    if (ncand < MAX_CAND) {
                        local_cand[ncand].ic = ic;
                        local_cand[ncand].r0 = r0; local_cand[ncand].r1 = r1; local_cand[ncand].r2 = r2;
                        local_cand[ncand].ref = sref[rf];
                        local_cand[ncand].p0 = p0; local_cand[ncand].p1 = p1; local_cand[ncand].p2 = p2;
                        local_cand[ncand].g0 = 0; local_cand[ncand].g1 = 0; local_cand[ncand].g2 = 0;
                        local_cand[ncand].thin = -1; local_cand[ncand].tp = -1;
                        ncand++;
                        if (ic < min_ic || ncand == 1) min_ic = ic;
                        if (ncand == MAX_CAND) {
                            min_ic = INT_MAX;
                            for (int k = 0; k < ncand; k++)
                                if (local_cand[k].ic < min_ic) min_ic = local_cand[k].ic;
                        }
                    } else if (ic > min_ic) {
                        int mi = 0;
                        for (int k = 1; k < ncand; k++)
                            if (local_cand[k].ic < local_cand[mi].ic) mi = k;
                        local_cand[mi] = local_cand[ncand-1];
                        ncand--;
                        local_cand[ncand].ic = ic;
                        local_cand[ncand].r0 = r0; local_cand[ncand].r1 = r1; local_cand[ncand].r2 = r2;
                        local_cand[ncand].ref = sref[rf];
                        local_cand[ncand].p0 = p0; local_cand[ncand].p1 = p1; local_cand[ncand].p2 = p2;
                        local_cand[ncand].g0 = 0; local_cand[ncand].g1 = 0; local_cand[ncand].g2 = 0;
                        local_cand[ncand].thin = -1; local_cand[ncand].tp = -1;
                        ncand++;
                        min_ic = INT_MAX;
                        for (int k = 0; k < ncand; k++)
                            if (local_cand[k].ic < min_ic) min_ic = local_cand[k].ic;
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

    memcpy(cand, local_cand, ncand * sizeof(Cand));
    return ncand;
}

static int cpu_phase1_m4(const char *ct, int n, int threshold, Cand *cand, int json_mode)
{
    int sr[8] = {R_I, R_II, R_III, R_IV, R_V, R_VI, R_VII, R_VIII};
    int sref[2] = {REF_B_THIN, REF_C_THIN};
    int thin_rotors[2] = {R_BETA, R_GAMMA};
    int idplug[26]; plug_init(idplug);

    Cand local_cand[MAX_CAND];
    int ncand = 0;
    int min_ic = 0;

    long long total = 2LL * 26 * 336 * 2 * 26*26*26;
    if (!json_mode) {
        printf("M4 Brute-force (CPU): %lld configs\n", total);
        printf("Phase 1: Searching rotor permutations and positions (rings=AAA)...\n");
    }
    fprintf(stderr, "PROGRESS:phase1:0:%lld\n", total);
    fflush(stderr);

    double t0 = now_sec();
    long long cnt = 0;

    #pragma omp parallel for collapse(2) schedule(dynamic) reduction(+:cnt) shared(local_cand, ncand, min_ic)
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
                    if (ic > threshold) {
                        #pragma omp critical(cand_m4)
                        {
                        if (ncand < MAX_CAND) {
                            local_cand[ncand].ic = ic;
                            local_cand[ncand].r0 = r0; local_cand[ncand].r1 = r1; local_cand[ncand].r2 = r2;
                            local_cand[ncand].ref = sref[rf];
                            local_cand[ncand].p0 = p0; local_cand[ncand].p1 = p1; local_cand[ncand].p2 = p2;
                            local_cand[ncand].g0 = 0; local_cand[ncand].g1 = 0; local_cand[ncand].g2 = 0;
                            local_cand[ncand].thin = thin_rotors[thi];
                            local_cand[ncand].tp = tp;
                            ncand++;
                            if (ic < min_ic || ncand == 1) min_ic = ic;
                            if (ncand == MAX_CAND) {
                                min_ic = INT_MAX;
                                for (int k = 0; k < ncand; k++)
                                    if (local_cand[k].ic < min_ic) min_ic = local_cand[k].ic;
                            }
                        } else if (ic > min_ic) {
                            int mi = 0;
                            for (int k = 1; k < ncand; k++)
                                if (local_cand[k].ic < local_cand[mi].ic) mi = k;
                            local_cand[mi] = local_cand[ncand-1];
                            ncand--;
                            local_cand[ncand].ic = ic;
                            local_cand[ncand].r0 = r0; local_cand[ncand].r1 = r1; local_cand[ncand].r2 = r2;
                            local_cand[ncand].ref = sref[rf];
                            local_cand[ncand].p0 = p0; local_cand[ncand].p1 = p1; local_cand[ncand].p2 = p2;
                            local_cand[ncand].g0 = 0; local_cand[ncand].g1 = 0; local_cand[ncand].g2 = 0;
                            local_cand[ncand].thin = thin_rotors[thi];
                            local_cand[ncand].tp = tp;
                            ncand++;
                            min_ic = INT_MAX;
                            for (int k = 0; k < ncand; k++)
                                if (local_cand[k].ic < min_ic) min_ic = local_cand[k].ic;
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

    memcpy(cand, local_cand, ncand * sizeof(Cand));
    return ncand;
}

/* ────────────────────────────────────────────────────────── */
/*  Unified cracker: GPU Phase 1 + CPU Phase 2/3               */
/* ────────────────────────────────────────────────────────── */

static CrackResult crack(const char *ct, int n, int is_m4, int json_mode, int force_cpu, const char *kernel_path)
{
    CrackResult result;
    memset(&result, 0, sizeof(result));
    result.is_m4 = is_m4;

    int thresh = (int)(0.035 * (double)n * (n - 1));

    Cand cand[MAX_CAND];
    int ncand = 0;
    long long config_count = 0;
    int used_gpu = 0;

    double t0 = now_sec();

    /* ── Phase 1: GPU or CPU brute force ── */
    if (!force_cpu && ocl_available()) {
        if (!json_mode)
            printf("Phase 1 (GPU/OpenCL): brute-force all rotor perms × positions with IC scoring...\n");
        int ret = gpu_phase1(is_m4, ct, n, thresh, cand, &config_count, json_mode, kernel_path);
        if (ret < 0) {
            if (!json_mode)
                printf("  GPU failed, falling back to CPU...\n");
            /* Fall through to CPU */
        } else {
            ncand = ret;
            used_gpu = 1;
        }
    }

    if (!used_gpu) {
        if (!json_mode)
            printf("Phase 1 (CPU%s): brute-force all rotor perms × positions with IC scoring...\n",
                   force_cpu ? " [forced]" : "");
        if (is_m4)
            ncand = cpu_phase1_m4(ct, n, thresh, cand, json_mode);
        else
            ncand = cpu_phase1_m3(ct, n, thresh, cand, json_mode);
        config_count = is_m4 ? (2LL*26*336*2*26*26*26) : (336LL*2*26*26*26);
    }

    if (ncand == 0) {
        if (!json_mode)
            printf("  *** No candidates found — try lowering threshold ***\n");
        result.elapsed = now_sec() - t0;
        result.configs = config_count;
        result.german_score = -1;
        return result;
    }

    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    /* ── Phase 2: ring search on all candidates (CPU) ── */
    int top_rings = ncand;
    if (!json_mode)
        printf("Phase 2: Ring search on all %d candidates (26³ = 17,576 rings each)...\n", top_rings);
    fprintf(stderr, "PROGRESS:phase2:0:%d\n", top_rings);
    fflush(stderr);

    int idplug[26]; plug_init(idplug);

    for (int c = 0; c < top_rings; c++) {
        int r0 = cand[c].r0, r1 = cand[c].r1, r2 = cand[c].r2;
        int rf = cand[c].ref;
        int p0 = cand[c].p0, p1 = cand[c].p1, p2 = cand[c].p2;
        int bg0 = 0, bg1 = 0, bg2 = 0;
        char tmp[512];

        if (is_m4) {
            int thin = cand[c].thin, tp = cand[c].tp;
            /* Use combined IC + German fitness for ring search (same as CPU).
               IC alone rarely distinguishes ring settings (it measures
               frequency distribution, which barely changes with rings).
               German word score responds to the actual decryption quality. */
            m4_encrypt(thin, r0,r1,r2, tp,p0,p1,p2, 0,0,0,0, rf, idplug, ct, n, tmp);
            int best_fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);

            for (int g0 = 0; g0 < 26; g0++)
            for (int g1 = 0; g1 < 26; g1++)
            for (int g2 = 0; g2 < 26; g2++) {
                m4_encrypt(thin, r0,r1,r2, tp,p0,p1,p2, 0,g0,g1,g2, rf, idplug, ct, n, tmp);
                int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
                if (fit > best_fit) { best_fit = fit; bg0 = g0; bg1 = g1; bg2 = g2; }
            }
            /* Update candidate IC to the IC at best rings (for re-sorting) */
            m4_encrypt(thin, r0,r1,r2, tp,p0,p1,p2, 0,bg0,bg1,bg2, rf, idplug, ct, n, tmp);
            cand[c].ic = ic_num(tmp, n);
        } else {
            /* Use combined IC + German fitness for ring search (same as CPU). */
            m3_encrypt(r0,r1,r2, p0,p1,p2, 0,0,0, rf, idplug, ct, n, tmp);
            int best_fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);

            for (int g0 = 0; g0 < 26; g0++)
            for (int g1 = 0; g1 < 26; g1++)
            for (int g2 = 0; g2 < 26; g2++) {
                m3_encrypt(r0,r1,r2, p0,p1,p2, g0,g1,g2, rf, idplug, ct, n, tmp);
                int fit = ic_num(tmp, n) * 100 + german_fitness(tmp, n);
                if (fit > best_fit) { best_fit = fit; bg0 = g0; bg1 = g1; bg2 = g2; }
            }
            /* Update candidate IC to the IC at best rings (for re-sorting) */
            m3_encrypt(r0,r1,r2, p0,p1,p2, bg0,bg1,bg2, rf, idplug, ct, n, tmp);
            cand[c].ic = ic_num(tmp, n);
        }

        cand[c].g0 = bg0; cand[c].g1 = bg1; cand[c].g2 = bg2;
        fprintf(stderr, "PROGRESS:phase2:%d:%d\n", c+1, top_rings);
        fflush(stderr);
    }

    qsort(cand, ncand, sizeof(Cand), cand_cmp);

    double t2 = now_sec();
    if (!json_mode)
        printf("  Done in %.2fs\n\n", t2-t0);

    /* ── Phase 3: hill climb plugboard on top 10 (CPU) ── */
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
        int bg0 = cand[c].g0, bg1 = cand[c].g1, bg2 = cand[c].g2;

        int plug[26];
        char out[512];
        int gs;

        if (is_m4) {
            int thin = cand[c].thin, tp = cand[c].tp;
            gs = hill_climb_m4(thin, r0,r1,r2, tp,p0,p1,p2, 0,bg0,bg1,bg2, rf, ct, n, plug, out);
        } else {
            gs = hill_climb_m3(r0,r1,r2, p0,p1,p2, bg0,bg1,bg2, rf, ct, n, plug, out);
        }

        if (!json_mode) {
            if (is_m4) {
                printf("  #%d  Thin %s  Rotors %s,%s,%s  Ref %s  ThinPos %c  Pos %c%c%c  Rings %c%c%c\n",
                       c+1,
                       ROTOR_NAME[cand[c].thin],
                       ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2],
                       REFLECTOR_NAME[rf],
                       cand[c].tp+'A',
                       p0+'A', p1+'A', p2+'A',
                       bg0+'A', bg1+'A', bg2+'A');
            } else {
                printf("  #%d  Rotors %s,%s,%s  Ref %s  Pos %c%c%c  Rings %c%c%c\n",
                       c+1,
                       ROTOR_NAME[r0], ROTOR_NAME[r1], ROTOR_NAME[r2],
                       REFLECTOR_NAME[rf],
                       p0+'A', p1+'A', p2+'A',
                       bg0+'A', bg1+'A', bg2+'A');
            }
            printf("       IC=%.4f  German=%d\n", ic_dbl(out, n), gs);
            printf("       Plug: ");
            for (int i = 0; i < 26; i++)
                if (plug[i] > i) printf("%c%c ", i+'A', plug[i]+'A');
            printf("\n       Text: %s\n\n", out);
        }

        fprintf(stderr, "PROGRESS:phase3:%d:%d\n", c+1, top_hc);
        fflush(stderr);

        if (gs > best_gs) {
            best_gs = gs;
            if (is_m4) { bThin = cand[c].thin; bTp = cand[c].tp; }
            bR0=r0; bR1=r1; bR2=r2; bRef=rf;
            bP0=p0; bP1=p1; bP2=p2;
            bG0=bg0; bG1=bg1; bG2=bg2;
            memcpy(best_plug, plug, sizeof(plug));
            strcpy(best_text, out);
        }
    }

    double t3 = now_sec();

    result.r0 = bR0; result.r1 = bR1; result.r2 = bR2;
    result.ref = bRef;
    result.p0 = bP0; result.p1 = bP1; result.p2 = bP2;
    result.g0 = bG0; result.g1 = bG1; result.g2 = bG2;
    if (is_m4) { result.thin = bThin; result.tp = bTp; result.tg = 0; }
    memcpy(result.plug, best_plug, sizeof(best_plug));
    strncpy(result.text, best_text, sizeof(result.text)-1);
    result.text[sizeof(result.text)-1] = '\0';
    result.german_score = best_gs;
    result.elapsed = t3 - t0;
    result.configs = config_count;

    if (!json_mode) {
        printf("════════════════════════════════════════\n");
        printf("BEST RESULT (%s, %s)\n", is_m4 ? "M4" : "M3", used_gpu ? "GPU" : "CPU");
        printf("════════════════════════════════════════\n");
        if (is_m4) {
            printf("Thin rotor:  %s\n", ROTOR_NAME[bThin]);
            printf("Thin Pos:    %c\n", bTp+'A');
        }
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
/*  JSON output                                                 */
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
    printf("  \"rings\": \"%c%c%c\",\n",
           r->g0+'A', r->g1+'A', r->g2+'A');
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
/*  CLI                                                         */
/* ────────────────────────────────────────────────────────── */

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
        "  --cpu              Force CPU fallback (no GPU)\n"
        "  --kernel <PATH>    Path to enigma_kernel.cl (default: search exe dir + cwd)\n"
        "  --help             Show this help\n"
        "\n"
        "If no --ct or --stdin is given, runs self-test mode.\n"
        "\n"
        "Examples:\n"
        "  %s --ct NCZWVUSXPNYMINHZXMQXSFWXWLKJAHSHNMCOCCAKUQPMKCSMHKSEINJUSBLK --mode M4\n"
        "  %s --ct CIPHERTEXT --mode M3 --cpu\n"
        "  echo CIPHERTEXT | %s --stdin --mode M4 --format json\n",
        prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    init_tables();
    load_dictionary_auto();

    const char *ct_arg = NULL;
    int use_stdin = 0;
    const char *mode_str = "M3";
    const char *format_str = "text";
    int json_mode = 0;
    int is_m4 = 0;
    int force_cpu = 0;
    const char *kernel_arg = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ct") == 0 && i + 1 < argc) {
            ct_arg = argv[++i];
        } else if (strcmp(argv[i], "--stdin") == 0) {
            use_stdin = 1;
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode_str = argv[++i];
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            format_str = argv[++i];
        } else if (strcmp(argv[i], "--cpu") == 0) {
            force_cpu = 1;
        } else if (strcmp(argv[i], "--kernel") == 0 && i + 1 < argc) {
            kernel_arg = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (strcmp(mode_str, "M4") == 0 || strcmp(mode_str, "m4") == 0) {
        is_m4 = 1;
    } else if (strcmp(mode_str, "M3") == 0 || strcmp(mode_str, "m3") == 0) {
        is_m4 = 0;
    } else {
        fprintf(stderr, "Invalid mode: %s (use M3 or M4)\n", mode_str);
        return 1;
    }

    if (strcmp(format_str, "json") == 0) {
        json_mode = 1;
    } else if (strcmp(format_str, "text") == 0) {
        json_mode = 0;
    } else {
        fprintf(stderr, "Invalid format: %s (use text or json)\n", format_str);
        return 1;
    }

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
        ct_n = -1;
    }

    /* Self-test mode */
    if (ct_n < 0) {
        if (json_mode) {
            fprintf(stderr, "Error: --format json requires --ct or --stdin\n");
            return 1;
        }

        printf("================================================================\n");
        printf("  ENIGMA CRACKER GPU — OpenCL + CPU Hybrid (M3 + M4)\n");
        printf("================================================================\n\n");

        /* Report OpenCL availability */
        if (ocl_available() && !force_cpu) {
            printf("OpenCL: available (GPU acceleration enabled)\n\n");
        } else {
            printf("OpenCL: %s (using CPU fallback)\n\n",
                   force_cpu ? "disabled (--cpu flag)" : "not available");
        }

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

        CrackResult r = crack(test_ct, test_n, 0, 0, force_cpu, kernel_arg);

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
        printf("  ENIGMA CRACKER GPU — %s mode\n", is_m4 ? "M4" : "M3");
        printf("================================================================\n\n");
        printf("Ciphertext (%d chars): %s\n\n", ct_n, ct);
    }

    CrackResult r = crack(ct, ct_n, is_m4, json_mode, force_cpu, kernel_arg);

    if (json_mode) {
        print_json_result(&r);
    }

    fprintf(stderr, "PROGRESS:done:0:0\n");
    fflush(stderr);

    return 0;
}