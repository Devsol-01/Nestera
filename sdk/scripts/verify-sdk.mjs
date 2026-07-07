import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(sdkRoot, '..');
const openApiPath = path.join(repoRoot, 'backend', 'openapi-v2.json');
const metadataPath = path.join(sdkRoot, 'src', 'metadata.ts');
const generatedIndexPath = path.join(sdkRoot, 'src', 'generated', 'index.ts');

execFileSync(process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm', ['run', 'generate:api-sdk'], {
  cwd: repoRoot,
  stdio: 'inherit',
});

for (const filePath of [openApiPath, metadataPath, generatedIndexPath]) {
  if (!existsSync(filePath)) {
    throw new Error(`Expected generated file not found: ${filePath}`);
  }
}

const openApi = JSON.parse(readFileSync(openApiPath, 'utf8'));
if (!openApi.components?.securitySchemes?.JWT) {
  throw new Error('OpenAPI document is missing the JWT security scheme.');
}

if (!openApi.components?.schemas?.StandardErrorResponseDto) {
  throw new Error('OpenAPI document is missing StandardErrorResponseDto.');
}

if (!openApi.components?.schemas?.PageMetaDto) {
  throw new Error('OpenAPI document is missing PageMetaDto.');
}
