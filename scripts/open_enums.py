"""Opens the generated models' response enums, so a value the API adds reads as served.

php-nextgen refuses a value outside the pinned spec while it deserializes: an inline enum
(`tier`, `license_type`, `outcome`) in its setter, and a referenced one (`standing`, a format)
because it is a native enum, which cannot hold another value. Both fail the whole call. This
drops the setters' checks and types the referenced members as strings, in the response models
alone: `Model/DatabaseFormat` stays an enum, and the request side refuses a format outside it
before the network.

    python3 scripts/open_enums.py src/Internal/Model
"""

import re
import sys

model = sys.argv[1]

# The members typed as a native enum in an answer, by file.
TYPED = {
    "Database.php": ["Standing"],
    "DatabaseFormatSize.php": ["DatabaseFormat"],
    "DatabaseVersion.php": ["DatabaseFormat"],
}
# The inline enums whose setter refuses a value outside the pinned spec, by file.
SETTERS = {"Database.php": 1, "Download.php": 1, "EntitlementPlan.php": 1}

CHECK = re.compile(
    r"\n {8}\$allowedValues = self::get\w+AllowableValues\(\);\n"
    r" {8}if \([^\n]*in_array\([^\n]*\)\) \{\n"
    r" {12}throw new InvalidArgumentException\(\n(?: {16}[^\n]*\n)+? {12}\);\n {8}\}"
)

opened = 0
for name, enums in TYPED.items():
    path = f"{model}/{name}"
    text = open(path).read()
    for enum in enums:
        full = re.escape(f"\\VPNDetection\\Internal\\Model\\{enum}") + r"(?![A-Za-z0-9_])"
        text, n = re.subn(full, "string", text)
        if n == 0:
            sys.exit(f"{path} no longer names {enum}: the model changed shape")
        opened += 1
    open(path, "w").write(text)
for name, want in SETTERS.items():
    path = f"{model}/{name}"
    text, n = CHECK.subn("", open(path).read())
    if n != want:
        sys.exit(f"{path}: {n} setter checks found, want {want}: the setter changed shape")
    open(path, "w").write(text)
    opened += n
print(f"  {opened} response enums opened")
