import * as fs from 'fs';
import * as path from 'path';

describe('OpenAPI Contract Tests', () => {
  let openApiSpec: any;

  beforeAll(() => {
    const specPath = path.join(__dirname, '../openapi-v2.json');
    if (!fs.existsSync(specPath)) {
      throw new Error(`OpenAPI spec not found at ${specPath}. Run 'pnpm run generate:openapi' first.`);
    }
    openApiSpec = JSON.parse(fs.readFileSync(specPath, 'utf-8'));
  });

  it('should match the snapshot', () => {
    expect(openApiSpec).toMatchSnapshot();
  });

  it('should have required paths', () => {
    const requiredPaths = [
      '/api/v2/auth/login',
      '/api/v2/auth/register',
    ];
    
    requiredPaths.forEach((path) => {
      expect(openApiSpec.paths).toHaveProperty(path);
    });
  });

  it('should have required components', () => {
    const requiredComponents = [
      'PageDto',
      'PaginatedResponseDto',
      'StandardErrorResponseDto',
    ];
    
    requiredComponents.forEach((component) => {
      expect(openApiSpec.components.schemas).toHaveProperty(component);
    });
  });
});
