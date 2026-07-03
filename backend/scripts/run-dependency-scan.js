#!/usr/bin/env node
const { spawnSync } = require('child_process');
const path = require('path');
const { buildScanReport, getAuditArgs, parseAuditJson, validateSuppressions, writeReport } = require('./dependency-scan-lib');

const backendDir = path.resolve(__dirname, '..');
const suppressionsPath = path.join(backendDir, '.dependency-suppressions.json');
const reportPath = path.join(backendDir, 'artifacts', 'dependency-scan-report.txt');
const threshold = process.env.SCA_THRESHOLD || 'high';

function readSuppressions(filePath) {
  if (!require('fs').existsSync(filePath)) {
    return [];
  }

  const content = require('fs').readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(content);
  return Array.isArray(parsed) ? parsed : [];
}

function runAudit(auditLevel) {
  const result = spawnSync('pnpm', getAuditArgs(auditLevel), {
    cwd: backendDir,
    encoding: 'utf8',
    env: process.env,
  });

  const stdout = result.stdout || '';
  const stderr = result.stderr || '';
  const combined = [stdout, stderr].filter(Boolean).join('\n').trim();

  if (result.status === 0 && !combined) {
    return { payload: { advisories: {} }, output: combined, exitCode: 0 };
  }

  const payload = parseAuditJson(stdout || '{}');
  return { payload, output: combined, exitCode: result.status || 0 };
}

function main() {
  const suppressions = validateSuppressions(readSuppressions(suppressionsPath));
  const { payload, output, exitCode } = runAudit(threshold);
  const report = buildScanReport(payload.advisories || {}, suppressions, threshold);
  writeReport(report, reportPath);

  console.log(output || 'Dependency audit completed.');
  console.log(`\nWrote dependency scan report to ${path.relative(backendDir, reportPath)}`);
  console.log(`Threshold: ${threshold}`);
  console.log(`Blocking advisories: ${report.blockingCount}`);
  console.log(`Suppressed advisories: ${report.suppressedCount}`);

  if (report.blockingCount > 0) {
    console.error(`Found ${report.blockingCount} blocking advisory(ies) with severity ${threshold} or higher.`);
    process.exit(1);
  }

  if (exitCode !== 0 && report.totalAdvisories === 0) {
    process.exit(exitCode);
  }

  process.exit(0);
}

main();
