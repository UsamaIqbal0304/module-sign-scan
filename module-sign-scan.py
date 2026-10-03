#!/usr/bin/env python3
"""What a Niagara station does with a module's signature, read from bytecode.

Reads com.tridium.nre.security.ModuleVerificationMode out of nre.jar,
com.tridium.sys.Nre and com.tridium.sys.module.ModuleClassLoader out of
baja.jar, and com.tridium.install.ModuleSignatureStatusEnum (with its
synthetic $1 switch-map class) out of platform-rt.jar, with javap - and
reports, from the bytecode rather than the docs:

  - the four verification modes and their ordinals, that DEFAULT is medium,
    and that below MIN_VERIFICATION_VERSION every mode collapses to low
  - the version thresholds in getDefaultVerificationMode (4.9, 4.10) that
    pick the mode when none is asked for
  - that Nre's field starts life as low in the static initialiser and is
    only replaced during init(), from baja's own module vendorVersion - an
    ordering fact, not a configured one
  - that the niagara.moduleVerificationMode property sits on a command-line
    denylist, so it cannot be set at the station command line
  - the acceptable/rejected signature-status table per mode, recovered from
    ModuleSignatureStatusEnum.isAcceptable by resolving the switch map
  - the ModuleClassLoader path: when an entry has no code signers, when a
    self-signed signing or timestamp certificate is refused rather than
    warned, and that an un-timestamped signature only warns - until the
    signing certificate expires
  - that disabling validation outright needs a licensed developer feature,
    and logs a three-line banner when it takes effect

Usage: ./module-sign-scan.py [NIAGARA_HOME]
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HOME = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
    "NIAGARA_HOME", "/opt/Niagara/Niagara-4.15.5.22")


def _find_javap(niagara_home=None):
    """javap from $JAVAP, then PATH, then the JDK Niagara ships, then Debian's."""
    cand = [os.environ.get("JAVAP"), shutil.which("javap")]
    for base in (os.environ.get("JAVA_HOME"), niagara_home):
        if base:
            cand += [str(Path(base) / "bin" / "javap"),
                     str(Path(base) / "jre" / "bin" / "javap")]
    cand.append("/usr/lib/jvm/java-8-openjdk-amd64/bin/javap")
    for c in cand:
        if c and Path(c).exists():
            return c
    return None


JAVAP = _find_javap(HOME)


def abort(why):
    sys.exit("ABORT %s" % why)


if not os.path.isdir(HOME):
    abort("no Niagara install at %s" % HOME)
if not JAVAP:
    abort("no javap found - set $JAVAP or put a JDK 8 javap on PATH")

TMP = tempfile.mkdtemp(prefix="msignscan-")
WANT = {
    os.path.join("bin", "ext", "nre.jar"): (
        "com/tridium/nre/security/ModuleVerificationMode",),
    os.path.join("modules", "baja.jar"): (
        "com/tridium/sys/Nre",
        "com/tridium/sys/module/ModuleClassLoader"),
    os.path.join("modules", "platform-rt.jar"): (
        "com/tridium/install/ModuleSignatureStatusEnum",),
}
for rel, prefixes in WANT.items():
    jar = os.path.join(HOME, rel)
    if not os.path.exists(jar):
        abort("no %s under %s" % (rel, HOME))
    with zipfile.ZipFile(jar) as z:
        names = [n for n in z.namelist()
                 if n.endswith(".class")
                 and any(n == p + ".class" or n.startswith(p + "$")
                         for p in prefixes)]
        if not names:
            abort("%s has no classes for %r" % (rel, prefixes))
        z.extractall(TMP, names)


def dis(cls):
    p = subprocess.run([JAVAP, "-p", "-c", "-constants", cls + ".class"],
                       cwd=TMP, capture_output=True, text=True)
    if p.returncode != 0 or "Compiled from" not in p.stdout:
        abort("javap failed on %s: %s" % (cls, p.stderr.strip()[:200]))
    return p.stdout


def method(text, sig, what):
    """Slice one member out of a javap dump, by signature.

    javap puts the exception table inside the member with no blank line
    before it, and exactly one blank line before the next member, so the
    first blank line is the right end marker.
    """
    i = text.find("  " + sig + ";\n")
    if i < 0:
        abort("no member %r in %s" % (sig, what))
    j = text.find("\n\n", i)
    return text[i:j if j > 0 else len(text)]


def one(hay, pat, what):
    m = re.findall(pat, hay)
    if len(m) != 1:
        abort("%d matches for %s (%r)" % (len(m), what, pat))
    return m[0]


def need(hay, s, what):
    if s not in hay:
        abort("expected %r in %s" % (s, what))
    return s


MVM = dis("com/tridium/nre/security/ModuleVerificationMode")
NRE = dis("com/tridium/sys/Nre")
MCL = dis("com/tridium/sys/module/ModuleClassLoader")
MSSE = dis("com/tridium/install/ModuleSignatureStatusEnum")
MSSE1 = dis("com/tridium/install/ModuleSignatureStatusEnum$1")

say = print

# ---- the four modes and their ordinals, read from the enum --------------
MVMINIT = method(MVM, "static {}", "ModuleVerificationMode")
ORD = {}
for name, lit in re.findall(
        r"ldc\s+#\d+\s+// String (\w+)\n"
        r"\s+\d+: (iconst_\d+)\n"
        r"\s+\d+: invokespecial\s+#\d+\s+// Method \"<init>\":", MVMINIT):
    ORD[name] = int(lit[len("iconst_"):])
for m in ("noPreference", "low", "medium", "high"):
    if m not in ORD:
        abort("ModuleVerificationMode has no %s" % m)
if sorted(ORD.values()) != [0, 1, 2, 3]:
    abort("the four mode ordinals are not 0..3: %r" % ORD)

# DEFAULT is whichever constant is copied into the DEFAULT field
DEFAULT = one(MVMINIT,
              r"getstatic\s+#\d+\s+// Field (\w+):"
              r"Lcom/tridium/nre/security/ModuleVerificationMode;\n"
              r"\s+\d+: putstatic\s+#\d+\s+// Field DEFAULT:", "DEFAULT")
# MIN_VERIFICATION_VERSION is the String fed to the Version before its store
MINVER = one(MVMINIT,
             r"ldc\s+#\d+\s+// String ([\d.]+)\n"
             r"\s+\d+: invokespecial\s+#\d+\s+// Method "
             r"com/tridium/nre/util/Version\.\"<init>\":\(Ljava/lang/String;\)V"
             r"\n\s+\d+: putstatic\s+#\d+\s+// Field MIN_VERIFICATION_VERSION:",
             "MIN_VERIFICATION_VERSION")

say("What a station does with a module signature")
say("=" * 70)
say("")
say("read from %s" % HOME)
jv = subprocess.run([JAVAP, "-version"], capture_output=True, text=True)
say("javap:    %s" % jv.stdout.strip() or jv.stderr.strip())
say("")
say("The verification mode is an enum of four, read out of nre.jar:")
for name in sorted(ORD, key=lambda n: ORD[n]):
    tag = []
    if name == DEFAULT:
        tag.append("DEFAULT")
    say("  %-13s ordinal %d%s" % (name, ORD[name],
                                  "   <- " + ",".join(tag) if tag else ""))
say("")
say("  Below version %s (MIN_VERIFICATION_VERSION) make() returns low" % MINVER)
say("  regardless of what is asked for. At or above it, a mode of")
say("  noPreference (or null) defers to getDefaultVerificationMode.")

# ---- getDefaultVerificationMode: the two version thresholds -------------
GDVM = method(MVM, "private static com.tridium.nre.security."
                   "ModuleVerificationMode getDefaultVerificationMode("
                   "com.tridium.nre.util.Version)",
              "getDefaultVerificationMode")
THRESH = re.findall(r"ldc\s+#\d+\s+// String ([\d.]+)\n"
                    r"\s+\d+: invokespecial\s+#\d+\s+// Method "
                    r"com/tridium/nre/util/Version\.\"<init>\"", GDVM)
if THRESH != ["4.9", "4.10"]:
    abort("getDefaultVerificationMode thresholds are %r, not 4.9/4.10"
          % (THRESH,))
# which mode each branch returns, in document order
GBRANCH = re.findall(r"getstatic\s+#\d+\s+// Field (\w+):"
                     r"Lcom/tridium/nre/security/ModuleVerificationMode;\n"
                     r"\s+\d+: areturn", GDVM)
say("")
say("  When no mode is asked for, getDefaultVerificationMode picks by")
say("  version: below %s -> %s; below %s -> %s; otherwise -> %s (the"
    % (THRESH[0], GBRANCH[0], THRESH[1], GBRANCH[1],
       GBRANCH[2] if GBRANCH[2] != "DEFAULT" else DEFAULT))
say("  shipped default). So a 4.14 or 4.15 controller lands on %s." % DEFAULT)

# ---- Nre: low first, replaced during init() -----------------------------
NREINIT = method(NRE, "static {}", "Nre")
need(NREINIT,
     "getstatic     #773                // Field "
     "com/tridium/nre/security/ModuleVerificationMode.low:", "Nre static init")
# the field it stores into, next line, must be moduleVerificationMode
if not re.search(r"// Field com/tridium/nre/security/ModuleVerificationMode"
                 r"\.low:Lcom/tridium/nre/security/ModuleVerificationMode;\n"
                 r"\s+\d+: putstatic\s+#\d+\s+// Field "
                 r"moduleVerificationMode:", NREINIT):
    abort("Nre's static initialiser no longer seeds moduleVerificationMode"
          " with low")
def member_containing(text, marker, what):
    """The method body that holds a marker, found by signature not by name.

    The mode is wired up inside Nre's boot sequence rather than a method
    called init, so slice by every member header and keep the one whose
    body actually stores moduleVerificationMode.
    """
    hits = []
    for mo in re.finditer(r"\n  ([A-Za-z].*?\([^;]*\)"
                          r"(?: throws [\w., ]+)?);\n", text):
        sig = mo.group(1)
        blk = method(text, sig, what)
        if marker in blk:
            hits.append((sig, blk))
    if len(hits) != 1:
        abort("%d members hold %r for %s" % (len(hits), marker, what))
    return hits[0][1]


NREI = member_containing(
    NRE, "// Method com/tridium/nre/security/ModuleVerificationMode.make:",
    "Nre boot")
need(NREI, "loadModule", "Nre.init")
need(NREI, "getVendorVersion", "Nre.init")
need(NREI, "// Method com/tridium/nre/security/ModuleVerificationMode.make:",
     "Nre.init")
if not re.search(r"ModuleVerificationMode\.make:\([^)]*\)"
                 r"Lcom/tridium/nre/security/ModuleVerificationMode;\n"
                 r"\s+\d+: putstatic\s+#\d+\s+// Field "
                 r"moduleVerificationMode:", NREI):
    abort("Nre.init no longer feeds make() back into moduleVerificationMode")
need(NREI, "Invalid argument provided for niagara.moduleVerificationMode "
           "property:", "Nre.init")
say("")
say("Where the mode actually comes from (Nre, in baja.jar):")
say("  The field moduleVerificationMode is seeded with low in Nre's static")
say("  initialiser. It is replaced during Nre.init(), which reads the")
say("  niagara.moduleVerificationMode property, loads the baja module and")
say("  passes make() baja's OWN vendorVersion - so the version that chooses")
say("  the default is the framework's, not the module's. An unparseable")
say("  property value logs a warning and leaves the requested mode null,")
say("  which make() then turns into the version default.")

# ---- the command-line denylist ------------------------------------------
DENY = one(NRE, r'private static final java.lang.String '
                r'DEFAULT_COMMAND_LINE_DENYLIST = "([^"]*)";',
           "DEFAULT_COMMAND_LINE_DENYLIST")
DENYITEMS = DENY.split(",")
need(DENY, "niagara.moduleVerificationMode", "the denylist")
say("")
say("  niagara.moduleVerificationMode is the first of %d entries on"
    % len(DENYITEMS))
say("  DEFAULT_COMMAND_LINE_DENYLIST, so it cannot be overridden at the")
say("  station command line - it has to be set in configuration:")
for it in DENYITEMS:
    say("    %s" % it)

# ---- the acceptable-status table, recovered from the switch map ---------
# values declared on the enum
VALUES = re.findall(
    r"public static final com\.tridium\.install\."
    r"ModuleSignatureStatusEnum (\w+);", MSSE)
if len(VALUES) != 9:
    abort("ModuleSignatureStatusEnum has %d values, expected 9: %r"
          % (len(VALUES), VALUES))
# switch-map: mode ordinal -> case label, from the $1 class
SMAP = {}  # modeName -> case int
for modename, lit in re.findall(
        r"getstatic\s+#\d+\s+// Field com/tridium/nre/security/"
        r"ModuleVerificationMode\.(\w+):"
        r"Lcom/tridium/nre/security/ModuleVerificationMode;\n"
        r"\s+\d+: invokevirtual\s+#\d+\s+// Method "
        r"com/tridium/nre/security/ModuleVerificationMode\.ordinal:\(\)I\n"
        r"\s+\d+: (iconst_\d+)\n\s+\d+: iastore", MSSE1):
    SMAP[modename] = int(lit[len("iconst_"):])
for m in ("low", "medium", "high"):
    if m not in SMAP:
        abort("switch map has no case for %s" % m)
# isAcceptable: tableswitch case -> entry offset, and the reject comparisons
ISACC = method(MSSE, "public boolean isAcceptable("
                     "com.tridium.nre.security.ModuleVerificationMode)",
               "isAcceptable")
CASES = {}  # case int -> entry offset
for lbl, off in re.findall(r"\s+(\d+): (\d+)\n", ISACC):
    CASES[int(lbl)] = int(off)
DEFOFF = int(one(ISACC, r"default: (\d+)\n", "isAcceptable default target"))
# every status comparison, with its offset
CMPS = [(int(off), name) for off, name in re.findall(
    r"\s+(\d+): getstatic\s+#\d+\s+// Field (\w+):"
    r"Lcom/tridium/install/ModuleSignatureStatusEnum;", ISACC)]
# the "accept everything" terminal is the first iconst_1 at/after default
ACCEPT_ALL = DEFOFF


def reject_set(entry):
    """Status names compared between a mode's entry offset and accept-all.

    The method is a fall-through chain: each mode enters at its own offset,
    rejects a few statuses, then falls into the next mode's block, down to
    the accept-all terminal. So the statuses named in [entry, accept-all)
    are exactly the ones that mode refuses.
    """
    return [n for off, n in CMPS if entry <= off < ACCEPT_ALL]


say("")
say("Which signature states each mode accepts (ModuleSignatureStatusEnum")
say(".isAcceptable, switch map resolved from the synthetic $1 class):")
say("")
MODES_BY_STRICT = ["noPreference", "low", "medium", "high"]
for mode in MODES_BY_STRICT:
    if mode == "noPreference":
        rej = []  # default case accepts everything
    else:
        entry = CASES.get(SMAP[mode])
        if entry is None:
            abort("no tableswitch entry for %s (case %d)"
                  % (mode, SMAP[mode]))
        rej = reject_set(entry)
    acc = [v for v in VALUES if v not in rej]
    say("  %-12s refuses: %s" % (mode, ", ".join(rej) if rej else "nothing"))
    say("  %-12s accepts: %s" % ("", ", ".join(acc)))
    say("")
say("  Note which line each mode draws. medium - the shipped default on")
say("  4.10 and up - accepts a self-signed signing certificate and an")
say("  un-timestamped signature; high refuses the self-signed one. No")
say("  mode below high ever refuses NOT_TIMESTAMPED on its own.")

# ---- ModuleClassLoader.verifyJarEntrySignature --------------------------
VJS = method(MCL, "boolean verifyJarEntrySignature(java.util.jar.JarEntry)",
             "verifyJarEntrySignature")
UNSIGNED = one(MCL, r'UNSIGNED = "([^"]*)";', "UNSIGNED message")
SIGNER_SS = one(MCL, r'SIGNER_SELF_SIGNED = "([^"]*)";', "SIGNER_SELF_SIGNED")
TS_SS = one(MCL, r'TIMESTAMP_SELF_SIGNED = "([^"]*)";', "TIMESTAMP_SELF_SIGNED")
NO_TS = one(MCL, r'NO_TIMESTAMP = "([^"]*)";', "NO_TIMESTAMP message")
CERT_FAIL = one(MCL, r'CERT_VALIDATION_FAILURE = "([^"]*)";',
                "CERT_VALIDATION_FAILURE")
# directories and META-INF entries are waved through
if not re.search(r"JarEntry\.isDirectory:\(\)Z\n\s+\d+: ifeq\s+\d+\n"
                 r"\s+\d+: iconst_1\n\s+\d+: ireturn", VJS):
    abort("verifyJarEntrySignature no longer returns true for a directory")
need(VJS, "// String META-INF", "verifyJarEntrySignature")
need(VJS, "// String com/tridium/", "verifyJarEntrySignature")
need(VJS, "// String javax/baja/", "verifyJarEntrySignature")
need(VJS, "NModule.getCheckTpk:()Z", "verifyJarEntrySignature")
# the no-code-signers fork: ValidationException when validating, else warn
need(VJS, "Error validating cert path: No code signers found.",
     "verifyJarEntrySignature")
need(VJS, UNSIGNED, "verifyJarEntrySignature")
# self-signed signer and timestamp are each compared against high
SS_GATES = re.findall(
    r"getstatic\s+#\d+\s+// Field com/tridium/nre/security/"
    r"ModuleVerificationMode\.high:"
    r"Lcom/tridium/nre/security/ModuleVerificationMode;\n"
    r"\s+\d+: if_acmpne", VJS)
if len(SS_GATES) != 2:
    abort("expected two high-mode gates in verifyJarEntrySignature, found %d"
          % len(SS_GATES))
need(VJS, "Self signed signing certificate not permitted by current module "
          "verification mode.", "verifyJarEntrySignature")
need(VJS, "Self signed timestamp certificate not permitted by current module "
          "verification mode.", "verifyJarEntrySignature")
need(VJS, NO_TS, "verifyJarEntrySignature")
need(VJS, CERT_FAIL, "verifyJarEntrySignature")
say("")
say("What ModuleClassLoader.verifyJarEntrySignature does, per entry:")
say("  Directories and META-INF entries return true without a check. The")
say("  cert chain is validated for an entry under com/tridium/ or")
say("  javax/baja/, or when the module sets checkTpk - and at mode low the")
say("  check is relaxed unless the module requested permissions.")
say("")
say("  No code signers on an entry that must be validated throws")
say("    \"Error validating cert path: No code signers found.\"")
say("  otherwise it only logs, and returns true:")
say("    \"%s\"" % UNSIGNED)
say("")
say("  A self-signed signing certificate is REFUSED only at mode high:")
say("    \"Self signed signing certificate not permitted by current")
say("     module verification mode.\"")
say("  and likewise a self-signed timestamp certificate. At medium and")
say("  low each is a warning only, worded \"... will not be allowed by")
say("  default in a future release.\"")
say("")
say("  An un-timestamped signature is accepted at every mode, with:")
say("    \"%s\"" % NO_TS)
say("  which is the one that bites an OEM later rather than now.")

# ---- disabling validation outright --------------------------------------
LSMV = method(MCL, "private static boolean loadSkipModuleValidation()",
              "loadSkipModuleValidation")
PROP = one(MCL, r'lambda\$loadSkipModuleValidation\$\d+\(\);'
                r'[\s\S]{0,200}?// String ([\w.]+)\n'
                r'\s+\d+: invokestatic\s+#\d+\s+// Method '
                r'java/lang/Boolean\.getBoolean:',
           "skip-validation property")
FEAT = re.findall(r"// String (\w+)\n\s+\d+: ldc\s+#\d+\s+// String (\w+)\n"
                  r"\s+\d+: invokeinterface\s+#\d+,\s+3\s+// InterfaceMethod "
                  r"javax/baja/license/LicenseManager\.checkFeature:", LSMV)
ATTR = one(LSMV, r'// String (\w+)\n\s+\d+: iconst_0\n'
                 r'\s+\d+: invokeinterface\s+#\d+,\s+3\s+// InterfaceMethod '
                 r'javax/baja/license/Feature\.getb:', "skip-validation attr")
need(LSMV, "A request to disable module validation was made, but the system "
           "is not licensed for it:", "loadSkipModuleValidation")
need(LSMV, "**** Module validation has been DISABLED ****",
     "loadSkipModuleValidation")
say("")
say("Turning validation off entirely:")
say("  The property %s is read, but" % PROP)
if FEAT:
    say("  it only takes effect behind a licensed feature - checkFeature(%r,"
        % FEAT[0][0])
    say("  %r) with the %r attribute. Without it the request" % (FEAT[0][1],
                                                                 ATTR))
    say("  throws FeatureNotLicensedException, is caught, and logs a warning:")
else:
    say("  it only takes effect behind a licensed developer feature. Without")
    say("  it the request is caught and logs a warning:")
say("    \"A request to disable module validation was made, but the system")
say("     is not licensed for it: ...\"")
say("  When it does take effect, a three-line banner is logged at WARNING:")
say("    \"**** Module validation has been DISABLED ****\" between two rows")
say("  of asterisks. There is no quiet way to switch it off.")

# ---- what this means for an OEM who signs its own jars ------------------
say("")
say("What this means if you ship a signed module")
say("-" * 70)
say("  1. On a 4.10+ controller the default is %s, which accepts a" % DEFAULT)
say("     self-signed certificate with only a warning. The same jar on a")
say("     site that has set the mode to high is refused outright. The mode")
say("     is not on the command line, so you find that out from the station")
say("     log, not from a platform switch you can read remotely.")
say("  2. NOT_TIMESTAMPED is acceptable in every mode - so a signed but")
say("     un-timestamped jar installs and runs today, and stops validating")
say("     the day the signing certificate expires. A timestamp is what")
say("     decouples 'signed then' from 'trusted now'.")
say("  3. Below %s the mode is forced to low and almost everything is" % MINVER)
say("     accepted; an older controller is not evidence your signing is")
say("     right, only that nothing checked it hard.")
say("  4. Nothing here is a defect. It is the shipped default and the shape")
say("     of the code that reads your signature - the parts an integrator")
say("     sees as a log line, and an OEM can get ahead of.")
