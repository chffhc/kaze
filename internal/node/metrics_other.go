//go:build !linux

package node

import "kaze/internal/proto"

// 非 Linux 平台不采集系统指标(节点端的正式运行环境是 Linux)。
type metricsCollector struct{}

func newMetricsCollector(string) *metricsCollector { return &metricsCollector{} }

func (m *metricsCollector) sample() proto.Metrics { return proto.Metrics{} }
