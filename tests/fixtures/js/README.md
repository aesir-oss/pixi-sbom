# JavaScript lockfiles

One small workspace project, locked by each tool that writes a format pixi-sbom reads (#29). The
project has a scoped package (`@sindresorhus/is`), a dependency with its own, older copy of a package
the project also uses (`debug` needs `ms@2.1.2`, the project has `ms@2.1.3`), a development dependency
(`is-number`), an optional one (`ms`), and a workspace member (`packages/util`, `@demo/util`).

Each lockfile was written by its own tool, from the same `package.json` files:

| Directory | Command (through `pixi exec --spec nodejs=22`) |
|---|---|
| `npm-v3` | `npm install --package-lock-only --ignore-scripts` (npm 10) |
| `npm-v2` | `npm install --package-lock-only --ignore-scripts --lockfile-version 2` |
| `yarn-v1` | `corepack yarn@1.22.22 install --ignore-scripts` (then `node_modules` removed) |
| `yarn-berry` | `corepack yarn@4.9.2 install --mode=update-lockfile` |
| `pnpm-v9` | `corepack pnpm@9.15.9 install --lockfile-only --ignore-scripts` |
| `pnpm-v6` | `corepack pnpm@8.15.9 install --lockfile-only --ignore-scripts` |
