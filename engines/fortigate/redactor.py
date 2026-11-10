"""Syntax-preserving secret redaction for FortiOS CLI configurations."""
import re
from dataclasses import dataclass
SENSITIVE_KEYS=frozenset({"access-key","api-key","auth-password","client-secret","community","group-password","key","password","passwd","pre-shared-key","private-key","priv-password","psksecret","secret","secret-key"})
_COMMAND=re.compile(r"^(?P<prefix>\s*(?:set|append)\s+(?P<key>[A-Za-z0-9_.-]+)\s+)(?P<value>.*?)(?P<newline>\r?\n?)$",re.I)
@dataclass(frozen=True)
class FortiGateRedactionResult: content:str; redacted_values:int
def _open(value):
    escaped=False; count=0
    for char in value:
        if escaped: escaped=False
        elif char=="\\": escaped=True
        elif char=='"': count+=1
    return count%2==1
def redact_fortigate_config(content:str|bytes,*,replacement:str="<REDACTED>",mapper=None):
    text=content.decode("utf-8-sig",errors="replace") if isinstance(content,bytes) else content
    output=[]; count=0; skipping=False
    for line in text.splitlines(keepends=True):
        if skipping:
            if _open(line): skipping=False
            continue
        match=_COMMAND.match(line)
        if not match or match.group("key").lower() not in SENSITIVE_KEYS: output.append(line); continue
        if mapper is not None:
            raw=match.group("value").strip()
            val=raw[1:-1] if len(raw)>=2 and raw[0]==raw[-1]=='"' else raw
            token=mapper.token(val,"SECRET")
        else:
            token=replacement
        output.append(f'{match.group("prefix")}"{token}"{match.group("newline")}'); count+=1; skipping=_open(match.group("value"))
    return FortiGateRedactionResult("".join(output),count)
