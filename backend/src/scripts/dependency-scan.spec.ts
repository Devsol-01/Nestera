import {
  buildScanReport,
  getAuditArgs,
  validateSuppressions,
} from '../../scripts/dependency-scan-lib';

describe('dependency scan report', () => {
  it('filters advisories above threshold and respects documented suppressions', () => {
    const advisories = {
      '1': {
        severity: 'high',
        module_name: 'foo',
        title: 'High issue',
        recommendation: 'Upgrade',
        findings: [{ paths: ['backend>foo'] }],
      },
      '2': {
        severity: 'critical',
        module_name: 'bar',
        title: 'Critical issue',
        recommendation: 'Upgrade',
        findings: [{ paths: ['backend>bar'] }],
      },
      '3': {
        severity: 'moderate',
        module_name: 'baz',
        title: 'Moderate issue',
        recommendation: 'Upgrade',
        findings: [{ paths: ['backend>baz'] }],
      },
    };

    const suppressions = [
      { advisoryId: '1', justification: 'Temporary migration exception' },
    ];
    const report = buildScanReport(advisories, suppressions, 'high');

    expect(report.blockingAdvisories).toHaveLength(1);
    expect(report.blockingAdvisories[0].id).toBe('2');
    expect(report.suppressedAdvisories).toHaveLength(1);
    expect(report.suppressedAdvisories[0].id).toBe('1');
  });

  it('rejects suppressions without a documented justification', () => {
    expect(() => validateSuppressions([{ advisoryId: '1' }])).toThrow(
      /justification/i,
    );
  });

  it('maps the configured threshold into the pnpm audit command', () => {
    expect(getAuditArgs('critical')).toEqual([
      'audit',
      '--prod',
      '--json',
      '--audit-level',
      'critical',
    ]);
    expect(getAuditArgs('HIGH')).toEqual([
      'audit',
      '--prod',
      '--json',
      '--audit-level',
      'high',
    ]);
  });
});
