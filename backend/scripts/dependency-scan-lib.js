const fs = require('fs');
const path = require('path');

function normalizeSeverity(value) {
  return String(value || 'low').toLowerCase();
}

function isBlockingSeverity(severity, threshold) {
  const order = ['low', 'moderate', 'high', 'critical'];
  const severityRank = order.indexOf(normalizeSeverity(severity));
  const thresholdRank = order.indexOf(normalizeSeverity(threshold));
  return severityRank >= thresholdRank;
}

function parseAuditJson(raw) {
  if (!raw || !raw.trim()) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`Unable to parse pnpm audit output: ${error.message}`);
  }
}

function getAuditArgs(threshold = 'high') {
  return ['audit', '--prod', '--json', '--audit-level', normalizeSeverity(threshold || 'high')];
}

function buildScanReport(advisories, suppressions = [], threshold = 'high') {
  const parsedSuppressions = Array.isArray(suppressions) ? suppressions : [];
  const suppressionById = new Map(
    parsedSuppressions
      .filter((item) => item && item.advisoryId)
      .map((item) => [String(item.advisoryId), item]),
  );

  const entries = Object.entries(advisories || {}).map(([id, advisory]) => ({
    id,
    severity: normalizeSeverity(advisory?.severity),
    moduleName: advisory?.module_name || 'unknown',
    title: advisory?.title || 'Unknown advisory',
    recommendation: advisory?.recommendation || 'No remediation guidance provided',
    paths: advisory?.findings?.flatMap((finding) => finding?.paths || []) || [],
  }));

  const matching = entries.filter((entry) => isBlockingSeverity(entry.severity, threshold));
  const suppressed = [];
  const blocking = [];

  for (const entry of matching) {
    const suppression = suppressionById.get(entry.id);
    if (suppression) {
      suppressed.push({ ...entry, justification: suppression.justification || '' });
    } else {
      blocking.push(entry);
    }
  }

  return {
    threshold,
    totalAdvisories: entries.length,
    blockingAdvisories: blocking,
    suppressedAdvisories: suppressed,
    blockingCount: blocking.length,
    suppressedCount: suppressed.length,
  };
}

function validateSuppressions(suppressions = []) {
  const parsed = Array.isArray(suppressions) ? suppressions : [];
  const invalid = parsed.filter((item) => !item?.advisoryId || !String(item.justification || '').trim());
  if (invalid.length) {
    throw new Error(`Each suppression must include an advisoryId and a documented justification. Missing: ${invalid.map((item) => item.advisoryId || 'unknown').join(', ')}`);
  }
  return parsed;
}

function writeReport(report, outputPath) {
  const content = [
    'Dependency vulnerability scan report',
    '==================================',
    `Threshold: ${report.threshold}`,
    `Total advisories: ${report.totalAdvisories}`,
    `Blocking advisories: ${report.blockingCount}`,
    `Suppressed advisories: ${report.suppressedCount}`,
    '',
    'Blocking advisories:',
    ...(report.blockingAdvisories.length
      ? report.blockingAdvisories.map((item) => `- [${item.severity.toUpperCase()}] ${item.id} ${item.moduleName}: ${item.title} (${item.recommendation})`)
      : ['- None']),
    '',
    'Suppressed advisories:',
    ...(report.suppressedAdvisories.length
      ? report.suppressedAdvisories.map((item) => `- [${item.severity.toUpperCase()}] ${item.id} ${item.moduleName}: ${item.title} | Justification: ${item.justification}`)
      : ['- None']),
    '',
  ].join('\n');

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, content, 'utf8');
  return content;
}

module.exports = {
  buildScanReport,
  getAuditArgs,
  normalizeSeverity,
  isBlockingSeverity,
  parseAuditJson,
  validateSuppressions,
  writeReport,
};
