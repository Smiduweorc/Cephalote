# Security Policy

## Supported versions

Cephalote is pre-1.0. Security fixes go to the latest release only, as a
patch release. That covers the AUR package, the release binaries and
`go install`.

Published advisories are listed in [ADVISORIES.md](./ADVISORIES.md).

## Reporting a vulnerability

Report it privately through GitHub: the "Report a vulnerability" button
under the Security tab of
[Smiduweorc/Cephalote](https://github.com/Smiduweorc/Cephalote/security/advisories/new).
That opens a private advisory only the maintainers can see. Please don't open
a public issue for it.

A weak algorithm Cephalote fails to flag is a normal bug, not a vulnerability:
open an issue with the snippet and the scheme you expected. Report privately
when the gap could hide weak crypto on purpose, such as a crafted file that
crashes the scan or makes it skip code, or anything in the release and
install path.

Useful to include: the version, how it was installed, the input that
triggers it, and the command line.

## What to expect

Cephalote is maintained by one person, as a side project. There is no
response-time promise. What is promised:

- every report gets read, and an answer saying whether it is accepted;
- an accepted report gets a fix, a test that reproduces it, a GitHub security
  advisory, and a CHANGELOG entry, in that release;
- you are credited in the advisory, unless you'd rather not be.
