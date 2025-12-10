// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// Histogram printing functions for libbpf tools

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "histogram.h"

/* Width of the histogram bar graph */
#define STARS_MAX 40

/* Print stars for the bar graph */
static void print_stars(unsigned long long val, unsigned long long val_max, int width)
{
    int num_stars;
    int i;

    if (val_max == 0) {
        num_stars = 0;
    } else {
        num_stars = (int)(val * width / val_max);
    }

    for (i = 0; i < num_stars; i++)
        printf("*");
}

/* Print a log2 histogram */
void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
    int stars_max = STARS_MAX;
    int idx_max = -1;
    unsigned int val_max = 0;
    int i;

    /* Find max index and value */
    for (i = 0; i < vals_size; i++) {
        if (vals[i] > 0)
            idx_max = i;
        if (vals[i] > val_max)
            val_max = vals[i];
    }

    if (idx_max < 0)
        return;

    /* Print header */
    if (idx_max <= 32) {
        printf("%5s%-19s : count    distribution\n", "", val_type);
    } else {
        printf("%15s%-29s : count    distribution\n", "", val_type);
    }

    /* Print histogram */
    for (i = 0; i <= idx_max; i++) {
        unsigned long long low = (1ULL << (i + 1)) >> 1;
        unsigned long long high = (1ULL << (i + 1)) - 1;
        int width;

        if (low == high)
            low = 0;

        width = idx_max <= 32 ? 10 : 20;
        printf("%*llu -> %-*llu : %-8u |", width, low, width, high, vals[i]);
        print_stars(vals[i], val_max, stars_max);
        printf("|\n");
    }
}

/* Print a log2 histogram with 64-bit values */
void print_log2_hist_u64(uint64_t *vals, int vals_size, const char *val_type)
{
    int stars_max = STARS_MAX;
    int idx_max = -1;
    uint64_t val_max = 0;
    int i;

    /* Find max index and value */
    for (i = 0; i < vals_size; i++) {
        if (vals[i] > 0)
            idx_max = i;
        if (vals[i] > val_max)
            val_max = vals[i];
    }

    if (idx_max < 0)
        return;

    /* Print header */
    if (idx_max <= 32) {
        printf("%5s%-19s : count    distribution\n", "", val_type);
    } else {
        printf("%15s%-29s : count    distribution\n", "", val_type);
    }

    /* Print histogram */
    for (i = 0; i <= idx_max; i++) {
        unsigned long long low = (1ULL << (i + 1)) >> 1;
        unsigned long long high = (1ULL << (i + 1)) - 1;
        int width;

        if (low == high)
            low = 0;

        width = idx_max <= 32 ? 10 : 20;
        printf("%*llu -> %-*llu : %-8lu |", width, low, width, high, (unsigned long)vals[i]);
        print_stars(vals[i], val_max, stars_max);
        printf("|\n");
    }
}

/* Print a linear histogram */
void print_linear_hist(unsigned int *vals, int vals_size,
                       unsigned int base, unsigned int step,
                       const char *val_type)
{
    int stars_max = STARS_MAX;
    int idx_min = -1, idx_max = -1;
    unsigned int val_max = 0;
    int i;

    /* Find min/max index and max value */
    for (i = 0; i < vals_size; i++) {
        if (vals[i] > 0) {
            if (idx_min < 0)
                idx_min = i;
            idx_max = i;
            if (vals[i] > val_max)
                val_max = vals[i];
        }
    }

    if (idx_max < 0)
        return;

    /* Print header */
    printf("%5s%-19s : count    distribution\n", "", val_type);

    /* Print histogram */
    for (i = idx_min; i <= idx_max; i++) {
        unsigned int low = base + (i * step);
        unsigned int high = low + step - 1;

        printf("%10u -> %-10u : %-8u |", low, high, vals[i]);
        print_stars(vals[i], val_max, stars_max);
        printf("|\n");
    }
}

/* Print a linear histogram with 64-bit values */
void print_linear_hist_u64(uint64_t *vals, int vals_size,
                           unsigned int base, unsigned int step,
                           const char *val_type)
{
    int stars_max = STARS_MAX;
    int idx_min = -1, idx_max = -1;
    uint64_t val_max = 0;
    int i;

    /* Find min/max index and max value */
    for (i = 0; i < vals_size; i++) {
        if (vals[i] > 0) {
            if (idx_min < 0)
                idx_min = i;
            idx_max = i;
            if (vals[i] > val_max)
                val_max = vals[i];
        }
    }

    if (idx_max < 0)
        return;

    /* Print header */
    printf("%5s%-19s : count    distribution\n", "", val_type);

    /* Print histogram */
    for (i = idx_min; i <= idx_max; i++) {
        unsigned int low = base + (i * step);
        unsigned int high = low + step - 1;

        printf("%10u -> %-10u : %-8lu |", low, high, (unsigned long)vals[i]);
        print_stars(vals[i], val_max, stars_max);
        printf("|\n");
    }
}

/* Calculate percentile from histogram */
int hist_percentile(unsigned int *vals, int vals_size, int percentile)
{
    unsigned long long total = 0;
    unsigned long long target;
    unsigned long long sum = 0;
    int i;

    if (percentile < 0 || percentile > 100)
        return -1;

    /* Calculate total */
    for (i = 0; i < vals_size; i++)
        total += vals[i];

    if (total == 0)
        return -1;

    target = (total * percentile) / 100;

    /* Find bucket containing percentile */
    for (i = 0; i < vals_size; i++) {
        sum += vals[i];
        if (sum >= target)
            return i;
    }

    return vals_size - 1;
}

/* Calculate percentile from histogram (64-bit) */
int hist_percentile_u64(uint64_t *vals, int vals_size, int percentile)
{
    uint64_t total = 0;
    uint64_t target;
    uint64_t sum = 0;
    int i;

    if (percentile < 0 || percentile > 100)
        return -1;

    /* Calculate total */
    for (i = 0; i < vals_size; i++)
        total += vals[i];

    if (total == 0)
        return -1;

    target = (total * percentile) / 100;

    /* Find bucket containing percentile */
    for (i = 0; i < vals_size; i++) {
        sum += vals[i];
        if (sum >= target)
            return i;
    }

    return vals_size - 1;
}

/* Print histogram statistics summary */
void print_hist_stats(unsigned int *vals, int vals_size, const char *val_type)
{
    unsigned long long total = 0;
    unsigned long long sum = 0;
    int min_idx = -1, max_idx = -1;
    int p50, p90, p99;
    int i;

    /* Find stats */
    for (i = 0; i < vals_size; i++) {
        if (vals[i] > 0) {
            if (min_idx < 0)
                min_idx = i;
            max_idx = i;
            total += vals[i];
            /* For average calculation, use midpoint of bucket */
            sum += vals[i] * ((1ULL << i) + (1ULL << (i + 1))) / 2;
        }
    }

    if (total == 0) {
        printf("No data collected\n");
        return;
    }

    p50 = hist_percentile(vals, vals_size, 50);
    p90 = hist_percentile(vals, vals_size, 90);
    p99 = hist_percentile(vals, vals_size, 99);

    printf("Statistics for %s:\n", val_type);
    printf("  count: %llu\n", total);
    printf("  min:   %llu %s\n", 1ULL << min_idx, val_type);
    printf("  max:   %llu %s\n", 1ULL << (max_idx + 1), val_type);
    printf("  avg:   %llu %s\n", total > 0 ? sum / total : 0, val_type);
    printf("  p50:   %llu %s\n", 1ULL << p50, val_type);
    printf("  p90:   %llu %s\n", 1ULL << p90, val_type);
    printf("  p99:   %llu %s\n", 1ULL << p99, val_type);
}

/* Print histogram statistics summary (64-bit) */
void print_hist_stats_u64(uint64_t *vals, int vals_size, const char *val_type)
{
    uint64_t total = 0;
    uint64_t sum = 0;
    int min_idx = -1, max_idx = -1;
    int p50, p90, p99;
    int i;

    /* Find stats */
    for (i = 0; i < vals_size; i++) {
        if (vals[i] > 0) {
            if (min_idx < 0)
                min_idx = i;
            max_idx = i;
            total += vals[i];
            sum += vals[i] * ((1ULL << i) + (1ULL << (i + 1))) / 2;
        }
    }

    if (total == 0) {
        printf("No data collected\n");
        return;
    }

    p50 = hist_percentile_u64(vals, vals_size, 50);
    p90 = hist_percentile_u64(vals, vals_size, 90);
    p99 = hist_percentile_u64(vals, vals_size, 99);

    printf("Statistics for %s:\n", val_type);
    printf("  count: %lu\n", (unsigned long)total);
    printf("  min:   %llu %s\n", 1ULL << min_idx, val_type);
    printf("  max:   %llu %s\n", 1ULL << (max_idx + 1), val_type);
    printf("  avg:   %lu %s\n", total > 0 ? (unsigned long)(sum / total) : 0UL, val_type);
    printf("  p50:   %llu %s\n", 1ULL << p50, val_type);
    printf("  p90:   %llu %s\n", 1ULL << p90, val_type);
    printf("  p99:   %llu %s\n", 1ULL << p99, val_type);
}
