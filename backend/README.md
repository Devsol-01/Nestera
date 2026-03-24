## Getting Started

### Prerequisites

- Node.js (v18 or higher)
- Docker & Docker Compose (optional, for local database)
- [pnpm](https://pnpm.io/) package manager (install via `npm i -g pnpm`)

### Installation

```bash
$ pnpm install
```

### Running the application

```bash
# development
$ pnpm run start

# watch mode
$ pnpm run start:dev

# production mode
$ pnpm run start:prod
```

### Running tests

```bash
# unit tests (required for CI/CD)
$ pnpm run test

# e2e tests
$ pnpm run test:e2e

# test coverage
$ pnpm run test:cov
```

## CI/CD Pipeline Checks

Before submitting a Pull Request, please ensure that your code passes the CI checks. The CI pipeline will automatically test and build your code.

To ensure your PR passes these checks locally, run:

```bash
# 1. Run unit tests - Must pass all tests
$ pnpm run test

# 2. Build the project - Must compile successfully
$ pnpm run build
```
