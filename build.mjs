import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = import.meta.dirname;
const SRC = join(ROOT, 'src');
const DIST = join(ROOT, 'dist');

const targets = process.argv.includes('--chrome')
  ? ['chrome']
  : process.argv.includes('--firefox')
    ? ['firefox']
    : ['chrome', 'firefox'];

for (const target of targets) {
  const out = join(DIST, target);

  // Clean and copy
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  cpSync(SRC, out, { recursive: true });

  // Patch manifest for Firefox
  if (target === 'firefox') {
    const manifestPath = join(out, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));

    manifest.browser_specific_settings = {
      gecko: {
        id: 'prompt-injection-detector@example.com',
        strict_min_version: '121.0'
      }
    };

    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  }

  console.log(`Built ${target} → dist/${target}/`);
}
