#!/usr/bin/env node

import { readFile } from 'fs/promises';
import { createLocalJWKSet, jwtVerify } from 'jose';

const jwt = await readFile(process.argv[2], 'utf8');
const jwks = JSON.parse(await readFile(process.argv[3], 'utf8'));

const jwkSet = createLocalJWKSet(jwks);
await jwtVerify(jwt, jwkSet, {
  issuer: 'https://example.com',
  audience: 'test-suite',
});
