/*
 * enigma_kernel.cl — OpenCL kernel for Enigma M3/M4 brute-force IC scoring
 *
 * Each work-item simulates the Enigma machine for one configuration
 * (rotor permutation × reflector × positions) and computes the Index
 * of Coincidence. Configurations above the IC threshold are written
 * to the output buffer using atomic operations.
 *
 * Candidate output layout (13 ints per candidate):
 *   [0]  ic       — IC numerator (Σ fᵢ(fᵢ-1))
 *   [1]  r0       — left rotor index
 *   [2]  r1       — middle rotor index
 *   [3]  r2       — right rotor index
 *   [4]  ref      — reflector index (absolute: 0=B, 1=C, 2=B_thin, 3=C_thin)
 *   [5]  p0       — left rotor start position
 *   [6]  p1       — middle rotor start position
 *   [7]  p2       — right rotor start position
 *   [8]  g0       — left ring setting (0 for Phase 1)
 *   [9]  g1       — middle ring setting (0 for Phase 1)
 *   [10] g2       — right ring setting (0 for Phase 1)
 *   [11] thin     — thin rotor index (8=beta, 9=gamma; -1 for M3)
 *   [12] tp       — thin rotor position (-1 for M3)
 *
 * Build: loaded at runtime by enigma_cracker_gpu.c
 */

/* ────────────────────────────────────────────────────────── */
/*  Modular reduction for values in [-25, 50]                   */
/* ────────────────────────────────────────────────────────── */

inline int m26(int x)
{
    if (x < 0)   return x + 26;
    if (x >= 26) return x - 26;
    return x;
}

/* ────────────────────────────────────────────────────────── */
/*  M3 kernel: 3-rotor Enigma, IC scoring                        */
/*                                                               */
/*  Global ID encodes:                                           */
/*    perm_id (336) × ref (2) × p0 (26) × p1 (26) × p2 (26)     */
/*  Total work items: 336 × 2 × 26³ = 11,803,392                */
/* ────────────────────────────────────────────────────────── */

__kernel void enigma_m3_ic(
    __constant int *rfwd,       /* 10×26: forward rotor wirings  */
    __constant int *rbwd,       /* 10×26: inverse rotor wirings  */
    __constant int *rnotch,     /* 10×26: notch positions (1=notch) */
    __constant int *refw,       /* 4×26:  reflector wirings      */
    __global   const int *perms,/* 336×3: rotor permutations [r0,r1,r2] */
    __constant int *ct,         /* ciphertext as 0–25 ints       */
    const int n,                /* ciphertext length             */
    const int threshold,        /* IC threshold                   */
    const int ref_base,         /* reflector base (0 for M3)      */
    __global   int *cand_count, /* atomic counter (initialized to 0) */
    __global   int *cand_out,   /* candidate output buffer        */
    const int max_cand           /* max candidates to store       */
)
{
    int gid = get_global_id(0);

    /* Decode configuration from global ID */
    int stride_ref  = 26 * 26 * 26;          /* 17576 */
    int stride_perm = 2 * stride_ref;        /* 35152 */

    int perm_id = gid / stride_perm;
    if (perm_id >= 336) return;

    int remainder = gid - perm_id * stride_perm;
    int ref = remainder / stride_ref;
    remainder -= ref * stride_ref;
    int p0 = remainder / (26 * 26);
    remainder -= p0 * (26 * 26);
    int p1 = remainder / 26;
    int p2 = remainder - p1 * 26;

    int r0 = perms[perm_id * 3];
    int r1 = perms[perm_id * 3 + 1];
    int r2 = perms[perm_id * 3 + 2];

    /* Enigma M3 simulation + frequency counting */
    /* Rings = AAA (g0=g1=g2=0), plugboard = identity */
    int pos0 = p0, pos1 = p1, pos2 = p2;
    int f[26] = {0};

    for (int i = 0; i < n; i++) {
        int c = ct[i];

        /* Step rotors (double-stepping logic) */
        if (rnotch[r1 * 26 + pos1]) {
            pos0 = pos0 + 1;
            if (pos0 >= 26) pos0 = 0;
            pos1 = pos1 + 1;
            if (pos1 >= 26) pos1 = 0;
        } else if (rnotch[r2 * 26 + pos2]) {
            pos1 = pos1 + 1;
            if (pos1 >= 26) pos1 = 0;
        }
        pos2 = pos2 + 1;
        if (pos2 >= 26) pos2 = 0;

        /* Forward: right → middle → left (rings = 0,0,0) */
        int o2 = pos2;
        c = m26(rfwd[r2 * 26 + m26(c + o2)] - o2);
        int o1 = pos1;
        c = m26(rfwd[r1 * 26 + m26(c + o1)] - o1);
        int o0 = pos0;
        c = m26(rfwd[r0 * 26 + m26(c + o0)] - o0);

        /* Reflector */
        c = refw[(ref + ref_base) * 26 + c];

        /* Backward: left → middle → right */
        c = m26(rbwd[r0 * 26 + m26(c + o0)] - o0);
        c = m26(rbwd[r1 * 26 + m26(c + o1)] - o1);
        c = m26(rbwd[r2 * 26 + m26(c + o2)] - o2);

        f[c]++;
    }

    /* Compute IC numerator: Σ fᵢ(fᵢ-1) */
    int ic = 0;
    for (int i = 0; i < 26; i++) ic += f[i] * (f[i] - 1);

    if (ic > threshold) {
        int idx = atomic_add(cand_count, 1);
        if (idx < max_cand) {
            int base = idx * 13;
            cand_out[base + 0]  = ic;
            cand_out[base + 1]  = r0;
            cand_out[base + 2]  = r1;
            cand_out[base + 3]  = r2;
            cand_out[base + 4]  = ref + ref_base;
            cand_out[base + 5]  = p0;
            cand_out[base + 6]  = p1;
            cand_out[base + 7]  = p2;
            cand_out[base + 8]  = 0;   /* g0 */
            cand_out[base + 9]  = 0;   /* g1 */
            cand_out[base + 10] = 0;   /* g2 */
            cand_out[base + 11] = -1;  /* thin (M3: not used) */
            cand_out[base + 12] = -1;  /* tp (M3: not used) */
        }
    }
}

/* ────────────────────────────────────────────────────────── */
/*  M4 kernel: 4-rotor Naval Enigma, IC scoring                 */
/*                                                               */
/*  Same 1D global ID as M3.  The thin rotor index and thin     */
/*  position are passed as kernel arguments.  The host loops    */
/*  over the 2×26 = 52 (thin, thin_pos) combinations,          */
/*  dispatching one batch per combination.                      */
/*                                                               */
/*  Per-batch work items: 336 × 2 × 26³ = 11,803,392            */
/*  Total: 52 × 11,803,392 = 613,776,384                        */
/* ────────────────────────────────────────────────────────── */

__kernel void enigma_m4_ic(
    __constant int *rfwd,
    __constant int *rbwd,
    __constant int *rnotch,
    __constant int *refw,
    __global   const int *perms,
    __constant int *ct,
    const int n,
    const int threshold,
    const int ref_base,     /* 2 for M4 (B_thin=2, C_thin=3) */
    const int thin,          /* thin rotor index (8=beta, 9=gamma) */
    const int tp,            /* thin rotor position (0–25) */
    __global   int *cand_count,
    __global   int *cand_out,
    const int max_cand
)
{
    int gid = get_global_id(0);

    int stride_ref  = 26 * 26 * 26;
    int stride_perm = 2 * stride_ref;

    int perm_id = gid / stride_perm;
    if (perm_id >= 336) return;

    int remainder = gid - perm_id * stride_perm;
    int ref = remainder / stride_ref;
    remainder -= ref * stride_ref;
    int p0 = remainder / (26 * 26);
    remainder -= p0 * (26 * 26);
    int p1 = remainder / 26;
    int p2 = remainder - p1 * 26;

    int r0 = perms[perm_id * 3];
    int r1 = perms[perm_id * 3 + 1];
    int r2 = perms[perm_id * 3 + 2];

    /* Enigma M4 simulation + frequency counting */
    /* Rings = AAAA (g0=g1=g2=tg=0), plugboard = identity */
    int pos0 = p0, pos1 = p1, pos2 = p2;
    int to = tp;  /* thin offset (tg = 0 in Phase 1) */
    int f[26] = {0};

    for (int i = 0; i < n; i++) {
        int c = ct[i];

        /* Step rotors (thin rotor never steps) */
        if (rnotch[r1 * 26 + pos1]) {
            pos0 = pos0 + 1;
            if (pos0 >= 26) pos0 = 0;
            pos1 = pos1 + 1;
            if (pos1 >= 26) pos1 = 0;
        } else if (rnotch[r2 * 26 + pos2]) {
            pos1 = pos1 + 1;
            if (pos1 >= 26) pos1 = 0;
        }
        pos2 = pos2 + 1;
        if (pos2 >= 26) pos2 = 0;

        /* Forward: right → middle → left → thin */
        int o2 = pos2;
        c = m26(rfwd[r2 * 26 + m26(c + o2)] - o2);
        int o1 = pos1;
        c = m26(rfwd[r1 * 26 + m26(c + o1)] - o1);
        int o0 = pos0;
        c = m26(rfwd[r0 * 26 + m26(c + o0)] - o0);
        c = m26(rfwd[thin * 26 + m26(c + to)] - to);

        /* Reflector (thin) */
        c = refw[(ref + ref_base) * 26 + c];

        /* Backward: thin → left → middle → right */
        c = m26(rbwd[thin * 26 + m26(c + to)] - to);
        c = m26(rbwd[r0 * 26 + m26(c + o0)] - o0);
        c = m26(rbwd[r1 * 26 + m26(c + o1)] - o1);
        c = m26(rbwd[r2 * 26 + m26(c + o2)] - o2);

        f[c]++;
    }

    int ic = 0;
    for (int i = 0; i < 26; i++) ic += f[i] * (f[i] - 1);

    if (ic > threshold) {
        int idx = atomic_add(cand_count, 1);
        if (idx < max_cand) {
            int base = idx * 13;
            cand_out[base + 0]  = ic;
            cand_out[base + 1]  = r0;
            cand_out[base + 2]  = r1;
            cand_out[base + 3]  = r2;
            cand_out[base + 4]  = ref + ref_base;
            cand_out[base + 5]  = p0;
            cand_out[base + 6]  = p1;
            cand_out[base + 7]  = p2;
            cand_out[base + 8]  = 0;   /* g0 */
            cand_out[base + 9]  = 0;   /* g1 */
            cand_out[base + 10] = 0;   /* g2 */
            cand_out[base + 11] = thin;
            cand_out[base + 12] = tp;
        }
    }
}