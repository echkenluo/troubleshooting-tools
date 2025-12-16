#!/usr/bin/env python
"""
CSV Statistics Processor

Calculates statistical metrics for CSV time-series data and appends to CSV files.
Implements 10 key statistics: mean, median, std, min, max, p95, p99, cv, non_zero_count, non_zero_mean
"""

import pandas as pd
import numpy as np
from typing import Dict, Optional


class CSVStatisticsProcessor:
    """CSV统计指标处理器"""

    # 统计指标列表（按输出顺序）
    STATISTICS = [
        'mean',
        'median',
        'std',
        'min',
        'max',
        'p95',
        'p99',
        'cv',
        'non_zero_count',
        'non_zero_mean'
    ]

    # 非数值列（不进行统计计算）
    NON_NUMERIC_COLUMNS = ['timestamp', 'connection', 'state', 'side']

    def calculate_column_statistics(self, series: pd.Series, col_name: str) -> Dict[str, any]:
        """
        计算单列的统计指标

        Args:
            series: 数据列
            col_name: 列名

        Returns:
            统计指标字典 {metric_name: value}
        """
        stats = {}

        # 非数值列跳过统计
        if col_name in self.NON_NUMERIC_COLUMNS:
            for metric in self.STATISTICS:
                stats[metric] = ''
            return stats

        # 转换为数值类型（忽略错误）
        numeric_series = pd.to_numeric(series, errors='coerce')

        # 移除NaN值
        valid_data = numeric_series.dropna()

        # 如果没有有效数据
        if len(valid_data) == 0:
            for metric in self.STATISTICS:
                stats[metric] = ''
            return stats

        # 计算基础统计量
        stats['mean'] = valid_data.mean()
        stats['median'] = valid_data.median()
        stats['std'] = valid_data.std()
        stats['min'] = valid_data.min()
        stats['max'] = valid_data.max()

        # 计算百分位数
        stats['p95'] = valid_data.quantile(0.95)
        stats['p99'] = valid_data.quantile(0.99)

        # 计算变异系数（CV = std/mean）
        mean_val = stats['mean']
        if mean_val != 0 and not pd.isna(mean_val):
            stats['cv'] = stats['std'] / mean_val
        else:
            stats['cv'] = ''  # 无法计算

        # 计算非零值统计
        non_zero_data = valid_data[valid_data != 0]
        stats['non_zero_count'] = len(non_zero_data)

        if len(non_zero_data) > 0:
            stats['non_zero_mean'] = non_zero_data.mean()
        else:
            stats['non_zero_mean'] = ''  # 没有非零值

        return stats

    def calculate_dataframe_statistics(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        计算整个DataFrame的统计指标

        Args:
            df: 原始数据DataFrame

        Returns:
            统计指标DataFrame，行是统计指标，列是原始列名
            注意：第一列（通常是timestamp）将被替换为metric名称
        """
        # 初始化统计结果字典
        stats_dict = {metric: {} for metric in self.STATISTICS}

        # 对每一列计算统计
        for col in df.columns:
            col_stats = self.calculate_column_statistics(df[col], col)

            for metric in self.STATISTICS:
                stats_dict[metric][col] = col_stats[metric]

        # 转换为DataFrame
        stats_df = pd.DataFrame(stats_dict).T

        # 第一列（原始数据的第一列，通常是timestamp）用metric名称替换
        first_col = df.columns[0]
        stats_df[first_col] = stats_df.index

        # 确保列顺序与原始DataFrame一致
        stats_df = stats_df[df.columns]
        stats_df.reset_index(drop=True, inplace=True)

        return stats_df

    def append_statistics_to_csv(self, csv_path: str) -> pd.DataFrame:
        """
        读取CSV，计算统计，追加到文件末尾

        追加格式：
        - 3个空行
        - [STATISTICS] 标记行
        - 10行统计数据

        Args:
            csv_path: CSV文件路径

        Returns:
            统计指标DataFrame（供分析模式使用）
        """
        # 读取CSV文件
        df = pd.read_csv(csv_path)

        # 计算统计指标
        stats_df = self.calculate_dataframe_statistics(df)

        # 准备追加内容
        with open(csv_path, 'a') as f:
            # 添加3个空行
            f.write('\n\n\n')

            # 添加标记行
            f.write('[STATISTICS]\n')

            # 写入统计数据（不带表头）
            stats_df.to_csv(f, index=False, header=False)

        return stats_df


def append_statistics_to_csv(csv_path: str) -> pd.DataFrame:
    """
    便捷函数：追加统计到CSV文件

    Args:
        csv_path: CSV文件路径

    Returns:
        统计指标DataFrame
    """
    processor = CSVStatisticsProcessor()
    return processor.append_statistics_to_csv(csv_path)
