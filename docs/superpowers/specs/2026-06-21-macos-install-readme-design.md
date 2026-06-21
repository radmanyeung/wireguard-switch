# macOS Installation README Design

## Goal

Make the Apple Silicon installation path understandable from both the GitHub
project page and the README bundled inside the macOS release ZIP.

## Scope

Update `README.md` and `docs/README-Mac.txt`. Do not change application code,
packaging scripts, dependencies, or release assets in this change.

## Documentation changes

The main README will gain a dedicated macOS Apple Silicon section that links
the release workflow to the commands users must run. The packaged Mac README
will retain its plain-text format while expanding its setup and troubleshooting
instructions.

Both files will explain how to:

1. Install `wireguard-tools` and Homebrew Bash.
2. Create `/opt/homebrew/etc/wireguard`.
3. Copy a real provider or server `.conf` file into that directory.
4. Protect configuration files with mode `600`.
5. Run the included dependency checker.
6. Remove the Chrome or browser quarantine attribute when macOS blocks launch.
7. Launch the executable from Terminal if Finder still cannot open the bundle.

Troubleshooting will distinguish an application launch failure from a tunnel
setup failure. It will also state that the release does not include WireGuard
configuration files because they commonly contain private keys.

## Validation

Review both files for matching commands, valid Markdown fences in `README.md`,
plain-text readability in `docs/README-Mac.txt`, and the absence of real private
configuration data. Confirm the Git working tree contains only the intended
documentation changes before committing and pushing.
