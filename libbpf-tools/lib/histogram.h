// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// Histogram printing functions for libbpf tools

#ifndef __HISTOGRAM_H
#define __HISTOGRAM_H

#include <stdint.h>

/* Maximum number of histogram slots */
#define MAX_SLOTS 26
#define MAX_SLOTS_LARGE 64

/*
 * Print a log2 histogram
 * @vals: array of histogram bucket values
 * @vals_size: number of buckets in the array
 * @val_type: label for the value type (e.g., "usecs", "bytes")
 */
void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type);

/*
 * Print a log2 histogram with 64-bit values
 * @vals: array of histogram bucket values (64-bit)
 * @vals_size: number of buckets in the array
 * @val_type: label for the value type (e.g., "usecs", "bytes")
 */
void print_log2_hist_u64(uint64_t *vals, int vals_size, const char *val_type);

/*
 * Print a linear histogram
 * @vals: array of histogram bucket values
 * @vals_size: number of buckets in the array
 * @base: base value of the first bucket
 * @step: step size between buckets
 * @val_type: label for the value type
 */
void print_linear_hist(unsigned int *vals, int vals_size,
                       unsigned int base, unsigned int step,
                       const char *val_type);

/*
 * Print a linear histogram with 64-bit values
 * @vals: array of histogram bucket values (64-bit)
 * @vals_size: number of buckets in the array
 * @base: base value of the first bucket
 * @step: step size between buckets
 * @val_type: label for the value type
 */
void print_linear_hist_u64(uint64_t *vals, int vals_size,
                           unsigned int base, unsigned int step,
                           const char *val_type);

/*
 * Calculate percentile from histogram
 * @vals: array of histogram bucket values
 * @vals_size: number of buckets
 * @percentile: percentile to calculate (0-100)
 *
 * Returns: the bucket index containing the percentile value
 */
int hist_percentile(unsigned int *vals, int vals_size, int percentile);

/*
 * Calculate percentile from histogram (64-bit)
 * @vals: array of histogram bucket values (64-bit)
 * @vals_size: number of buckets
 * @percentile: percentile to calculate (0-100)
 *
 * Returns: the bucket index containing the percentile value
 */
int hist_percentile_u64(uint64_t *vals, int vals_size, int percentile);

/*
 * Print histogram statistics summary
 * @vals: array of histogram bucket values
 * @vals_size: number of buckets
 * @val_type: label for the value type
 *
 * Prints: min, max, avg, p50, p90, p99, count
 */
void print_hist_stats(unsigned int *vals, int vals_size, const char *val_type);

/*
 * Print histogram statistics summary (64-bit)
 * @vals: array of histogram bucket values
 * @vals_size: number of buckets
 * @val_type: label for the value type
 */
void print_hist_stats_u64(uint64_t *vals, int vals_size, const char *val_type);

#endif /* __HISTOGRAM_H */
