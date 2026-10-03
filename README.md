# module-sign-scan

What a Niagara station actually does with your module's signature, read out of
the bytecode that reads it.

One Python file, standard library only. It reads `nre.jar`, `baja.jar` and
`platform-rt.jar` from a Niagara installation with `javap` and prints the
verification modes, the signature states each one accepts, and the exact log
lines the station emits.

```
./module-sign-scan.py [NIAGARA_HOME]
```

## Why this exists

If you ship a Niagara module, the question that matters is not "is it signed"
but "which of the four verification modes will refuse it, and on whose
controller". Two answers out of the bytecode are worth knowing before a
customer finds them:

- **The shipped default, medium, accepts a self-signed signing certificate**
  with a warning. The same jar on a site that has set the mode to high is
  refused outright - and `niagara.moduleVerificationMode` is the first entry on
  a command-line denylist, so you learn which mode a site runs from its station
  log, not from a switch you can read remotely.
- **An un-timestamped signature is acceptable in every mode.** It installs and
  runs today, and stops validating the day the signing certificate expires. The
  station says so when it loads the module, in a line most people never read.

Neither is a defect. Both are the shipped behaviour, and an OEM can get ahead
of them.

## What it reads, and where from

- `ModuleVerificationMode` - the four modes and their ordinals, that `DEFAULT`
  is medium, that below `MIN_VERIFICATION_VERSION` every mode collapses to low,
  and the version thresholds `getDefaultVerificationMode` uses.
- `Nre` - that the field starts as low in the static initialiser and is only
  replaced during `init()`, from **baja's own** module vendorVersion, so the
  version that picks the default is the framework's and not the module's. Also
  the command-line denylist, printed in full.
- `ModuleSignatureStatusEnum.isAcceptable` - the accept/refuse table per mode,
  recovered by resolving the synthetic `$1` switch-map class.
- `ModuleClassLoader.verifyJarEntrySignature` - which entries are checked at
  all, when a missing code signer throws rather than warns, when a self-signed
  certificate is refused rather than warned, and the verbatim log lines.
- The `skipModuleValidation` path, including the licensed feature it needs and
  the banner it logs when it takes effect.

## Read first: what it does and does not touch

**It never connects to a station, a device or a network, and it does not sign,
verify or modify any jar.** It unzips jars and runs `javap`. Nothing is
installed, patched, written to a station or sent anywhere.

It needs a Niagara installation to read and a `javap` from a JDK 8. It looks
for `javap` in `$JAVAP`, then on `PATH`, then under `$JAVA_HOME` and the
Niagara install, then in Debian's default location. The install to read comes
from the first argument or `$NIAGARA_HOME`.

**The output below was measured against Niagara 4.15.5.22.** Another version
may differ - the version thresholds in here make that likely - so rerun it
against the version your customer runs rather than trusting this page.

## Running it

```
$ ./module-sign-scan.py
What a station does with a module signature
======================================================================

read from /opt/Niagara/Niagara-4.15.5.22
javap:    1.8.0_504

The verification mode is an enum of four, read out of nre.jar:
  noPreference  ordinal 0
  low           ordinal 1
  medium        ordinal 2   <- DEFAULT
  high          ordinal 3

  Below version 4.8 (MIN_VERIFICATION_VERSION) make() returns low
  regardless of what is asked for. At or above it, a mode of
  noPreference (or null) defers to getDefaultVerificationMode.

  When no mode is asked for, getDefaultVerificationMode picks by
  version: below 4.9 -> low; below 4.10 -> medium; otherwise -> medium (the
  shipped default). So a 4.14 or 4.15 controller lands on medium.

Where the mode actually comes from (Nre, in baja.jar):
  The field moduleVerificationMode is seeded with low in Nre's static
  initialiser. It is replaced during Nre.init(), which reads the
  niagara.moduleVerificationMode property, loads the baja module and
  passes make() baja's OWN vendorVersion - so the version that chooses
  the default is the framework's, not the module's. An unparseable
  property value logs a warning and leaves the requested mode null,
  which make() then turns into the version default.

  niagara.moduleVerificationMode is the first of 8 entries on
  DEFAULT_COMMAND_LINE_DENYLIST, so it cannot be overridden at the
  station command line - it has to be set in configuration:
    niagara.moduleVerificationMode
    program.requireSigning
    niagara.export.preventCSVInjection
    niagara.webbrowser.disable
    niagara.webbrowser.urlWhitelist
    niagara.baja.formatBlacklist
    niagara.baja.formatBlacklistExclusions
    jdk.tls.rejectClientInitiatedRenegotiation

Which signature states each mode accepts (ModuleSignatureStatusEnum
.isAcceptable, switch map resolved from the synthetic $1 class):

  noPreference refuses: nothing
               accepts: OK, NOT_TIMESTAMPED, UNKNOWN, SIGNER_SELF_SIGNED, TIMESTAMP_SELF_SIGNED, CERT_PATH_VALIDATION_FAILURE, CERT_PATH_VALIDATION_WARNING, UNSIGNED, INVALID_SIGNATURE

  low          refuses: INVALID_SIGNATURE
               accepts: OK, NOT_TIMESTAMPED, UNKNOWN, SIGNER_SELF_SIGNED, TIMESTAMP_SELF_SIGNED, CERT_PATH_VALIDATION_FAILURE, CERT_PATH_VALIDATION_WARNING, UNSIGNED

  medium       refuses: UNSIGNED, CERT_PATH_VALIDATION_FAILURE, UNKNOWN, INVALID_SIGNATURE
               accepts: OK, NOT_TIMESTAMPED, SIGNER_SELF_SIGNED, TIMESTAMP_SELF_SIGNED, CERT_PATH_VALIDATION_WARNING

  high         refuses: SIGNER_SELF_SIGNED, TIMESTAMP_SELF_SIGNED, UNSIGNED, CERT_PATH_VALIDATION_FAILURE, UNKNOWN, INVALID_SIGNATURE
               accepts: OK, NOT_TIMESTAMPED, CERT_PATH_VALIDATION_WARNING

  Note which line each mode draws. medium - the shipped default on
  4.10 and up - accepts a self-signed signing certificate and an
  un-timestamped signature; high refuses the self-signed one. No
  mode below high ever refuses NOT_TIMESTAMPED on its own.

What ModuleClassLoader.verifyJarEntrySignature does, per entry:
  Directories and META-INF entries return true without a check. The
  cert chain is validated for an entry under com/tridium/ or
  javax/baja/, or when the module sets checkTpk - and at mode low the
  check is relaxed unless the module requested permissions.

  No code signers on an entry that must be validated throws
    "Error validating cert path: No code signers found."
  otherwise it only logs, and returns true:
    "No code signers for entry %s in module %s. Signed modules will be required in a future release."

  A self-signed signing certificate is REFUSED only at mode high:
    "Self signed signing certificate not permitted by current
     module verification mode."
  and likewise a self-signed timestamp certificate. At medium and
  low each is a warning only, worded "... will not be allowed by
  default in a future release."

  An un-timestamped signature is accepted at every mode, with:
    "Signature for entry %s in module %s is not timestamped. This signature will fail to validate when the signing certificate expires."
  which is the one that bites an OEM later rather than now.

Turning validation off entirely:
  The property niagara.classLoader.skipModuleValidation is read, but
  it only takes effect behind a licensed feature - checkFeature('tridium',
  'developer') with the 'skipModuleValidation' attribute. Without it the request
  throws FeatureNotLicensedException, is caught, and logs a warning:
    "A request to disable module validation was made, but the system
     is not licensed for it: ..."
  When it does take effect, a three-line banner is logged at WARNING:
    "**** Module validation has been DISABLED ****" between two rows
  of asterisks. There is no quiet way to switch it off.

What this means if you ship a signed module
----------------------------------------------------------------------
  1. On a 4.10+ controller the default is medium, which accepts a
     self-signed certificate with only a warning. The same jar on a
     site that has set the mode to high is refused outright. The mode
     is not on the command line, so you find that out from the station
     log, not from a platform switch you can read remotely.
  2. NOT_TIMESTAMPED is acceptable in every mode - so a signed but
     un-timestamped jar installs and runs today, and stops validating
     the day the signing certificate expires. A timestamp is what
     decouples 'signed then' from 'trusted now'.
  3. Below 4.8 the mode is forced to low and almost everything is
     accepted; an older controller is not evidence your signing is
     right, only that nothing checked it hard.
  4. Nothing here is a defect. It is the shipped default and the shape
     of the code that reads your signature - the parts an integrator
     sees as a log line, and an OEM can get ahead of.
```

## The same finding, written up

The output above, the four verification modes, the signature state each one refuses, and the log lines a station writes, is also a page: <https://plantroomlabs.com/tools/module-sign-scan/>. It carries this run, the download with its size and SHA-256, and the note explaining the reasoning.

## Licence

MIT. Written by Usama Iqbal at [Plantroom Labs](https://plantroomlabs.com).
