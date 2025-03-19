# hashsigs-ts

Hash-based signatures implementation in TypeScript, featuring WOTS+ (Winternitz One-Time Signature Plus).

## License

SPDX-License-Identifier: AGPL-3.0-or-later  
Copyright (C) 2024 quip.network

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

## Installation

```bash
npm install hashsigs-ts
```

## Development

### Setup

```bash
# Install dependencies
npm install
```

### Building

```bash
# Build once
npm run build

# Watch mode during development
npm run dev
```

### Testing

The project uses Vitest for testing with the following commands:

```bash
# Run tests once
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run coverage
```

### Code Coverage

The project maintains high code coverage standards with the following minimum thresholds:
- Functions: 80%
- Branches: 80%
- Statements: 80%

To view coverage reports:

1. Run the coverage command:
   ```bash
   npm run coverage
   ```

2. Coverage reports will be generated in multiple formats:
   - Console output (summary)
   - HTML report (in `./coverage/index.html`)
   - JSON report
   - LCOV report (for CI/CD integration)

## Repository

- GitHub: [https://github.com/quipnetwork/hashsigs-ts](https://github.com/quipnetwork/hashsigs-ts)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure all tests pass and coverage thresholds are met before submitting a PR.