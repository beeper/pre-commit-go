package rules

import "golang.org/x/tools/go/analysis"

// Analyzers are the bridgelint rule groups, in the order they're documented.
var Analyzers = []*analysis.Analyzer{MSSAnalyzer, BSAnalyzer, LPAnalyzer, EPAnalyzer, GRAnalyzer}
