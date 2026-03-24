# NestJS Secure API

A NestJS application with Helmet and CORS security configured.

## Security Features

- **Helmet**: Secures HTTP headers to prevent common vulnerabilities
- **CORS**: Configured to allow specific origins with credentials support
- **Environment-based configuration**: Different settings for development and production

## Installation

```bash
npm install
```

## Environment Variables

Copy `.env.example` to `.env` and configure:

- `PORT`: Application port (default: 3000)
- `NODE_ENV`: Environment (development/production)
- `ALLOWED_ORIGINS`: Comma-separated list of allowed origins for CORS

## Running the Application

```bash
# Development
npm run start:dev

# Production build
npm run build
npm run start:prod
```

## CORS Configuration

- **Development**: Allows all origins (`*`)
- **Production**: Only allows origins specified in `ALLOWED_ORIGINS` environment variable

## Testing CORS

```bash
# Test from allowed origin
curl -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS http://localhost:3000/health

# Check security headers
curl -I http://localhost:3000/health
```

## Security Headers (Helmet)

Helmet automatically sets the following headers:

- Content-Security-Policy
- X-DNS-Prefetch-Control
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- X-Download-Options
- X-Permitted-Cross-Domain-Policies
