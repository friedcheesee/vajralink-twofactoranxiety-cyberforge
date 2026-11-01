"""
Vajra Java Taint Engine - generic, target-agnostic source-to-sink analysis for ordinary Spring / servlet code.

No filename, class-name, line-number or benchmark-string is used anywhere in this module.  It works like this:

  1. Parse every .java file into methods (text parser, string/comment aware) and a project-wide method table.
  2. Entry points = methods carrying a *Mapping / JAX-RS annotation or servlet doGet/doPost. Their request-bound
     parameters (@RequestParam, @PathVariable, @RequestBody, @RequestHeader, @CookieValue, unannotated bound params,
     HttpServletRequest) are taint sources; so are request.getParameter/getHeader/getQueryString/getInputStream...
  3. Walk each method statement by statement tracking per-vulnerability-class taint through locals, string
     concatenation, String.format, StringBuilder.append, collections, for-each, ternaries.
  4. When a call passes tainted arguments to a resolvable method (same class helper, @Service via DI, interface
     implementation, static call) the callee is analysed with those parameters tainted (depth <= 4).
  5. Sinks (SQLi, command injection, path traversal, open redirect, XSS) fire only when the argument carries
     taint of that class. Sanitisers (htmlEscape, parseInt, getFileName ...) remove classes; validators
     (regex .matches, allow-list .contains, startsWith(base) ...) neutralise a variable; fully constant or
     parameterised sinks are emitted as suppressed decoys with a reason.

Limits (honest): text-based analysis, call depth 4. No alias analysis, no field-sensitivity beyond "an object holding
tainted data is tainted", no stored (second-order) flows, no reflection, no lambda data-flow.
"""
from __future__ import annotations

import os
import re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from vajra.models import CommonFinding, canonicalize_cwe
from vajra.sast.engines import ENGINE_AST_TAINT, ENGINE_DECOY

SCANNER = "Vajra-Java-Taint"

SQL, CMD, PATH, REDIR, XSS = "sql", "cmd", "path", "redir", "xss"
ALL: FrozenSet[str] = frozenset({SQL, CMD, PATH, REDIR, XSS})
EMPTY: FrozenSet[str] = frozenset()

KEYWORDS = {"if", "for", "while", "catch", "switch", "synchronized", "new", "super", "this", "return", "throw",
            "else", "try", "assert", "instanceof", "case", "do", "finally"}

# ---------------------------------------------------------------------------------------- low-level text utils


def mask_text(t: str) -> str:
    """Same length; comments -> spaces, string/char literal interiors -> '~' (quotes kept)."""
    out = list(t)
    i, n = 0, len(t)
    while i < n:
        c = t[i]
        if c == "/" and i + 1 < n and t[i + 1] == "/":
            while i < n and t[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and t[i + 1] == "*":
            j = t.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if t[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c == '"' and t.startswith('"""', i):
            j = t.find('"""', i + 3)
            j = n if j < 0 else j + 3
            for k in range(i + 3, max(i + 3, j - 3)):
                if t[k] != "\n":
                    out[k] = "~"
            i = j
            continue
        if c in "\"'":
            j = i + 1
            while j < n and t[j] != c and t[j] != "\n":
                j += 2 if t[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = "~"
            i = j + 1
            continue
        i += 1
    return "".join(out)


def blank_comments(t: str) -> str:
    """Original text with comments blanked (strings intact), same length."""
    out = list(t)
    i, n = 0, len(t)
    while i < n:
        c = t[i]
        if c == "/" and i + 1 < n and t[i + 1] == "/":
            while i < n and t[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and t[i + 1] == "*":
            j = t.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if t[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c in "\"'":
            if t.startswith('"""', i):
                j = t.find('"""', i + 3)
                i = n if j < 0 else j + 3
                continue
            j = i + 1
            while j < n and t[j] != c and t[j] != "\n":
                j += 2 if t[j] == "\\" else 1
            i = j + 1
            continue
        i += 1
    return "".join(out)


def match_close(m: str, i: int, o: str, c: str) -> int:
    d = 0
    for j in range(i, len(m)):
        if m[j] == o:
            d += 1
        elif m[j] == c:
            d -= 1
            if d == 0:
                return j
    return -1


def split_top(s: str, seps: str = ",", angle: bool = False) -> List[Tuple[int, str]]:
    out, depth, start = [], 0, 0
    for i, ch in enumerate(s):
        if ch in "([{" or (angle and ch == "<"):
            depth += 1
        elif ch in ")]}" or (angle and ch == ">"):
            depth -= 1
        elif ch in seps and depth == 0:
            out.append((start, s[start:i]))
            start = i + 1
    out.append((start, s[start:]))
    return out


def call_args(masked: str, orig: str, open_idx: int) -> List[str]:
    """Arguments of the call whose '(' is at open_idx (masked and orig must be index-aligned)."""
    close = match_close(masked, open_idx, "(", ")")
    if close < 0:
        close = len(masked)
    inner_m = masked[open_idx + 1:close]
    res = []
    for off, piece in split_top(inner_m, ","):
        a, b = open_idx + 1 + off, open_idx + 1 + off + len(piece)
        res.append(orig[a:b].strip())
    if len(res) == 1 and not res[0]:
        return []
    return res


# ------------------------------------------------------------------------------------------------ constants
NUMERIC_TYPES = {"int", "long", "short", "byte", "double", "float", "boolean", "char", "Integer", "Long", "Short",
                 "Byte", "Double", "Float", "Boolean", "UUID", "BigDecimal", "BigInteger", "LocalDate",
                 "LocalDateTime", "Instant", "Date", "Character"}
NON_BOUND_TYPES = {"HttpServletResponse", "ServletResponse", "Model", "ModelMap", "BindingResult", "Principal",
                   "Locale", "HttpSession", "RedirectAttributes", "Authentication", "Pageable", "Errors",
                   "OutputStream", "Writer", "PrintWriter", "SessionStatus", "UriComponentsBuilder",
                   "HttpMethod", "TimeZone", "ZoneId"}
REQ_HOLDER_TYPES = {"HttpServletRequest", "ServletRequest", "WebRequest", "NativeWebRequest", "RequestEntity",
                    "HttpEntity", "MultipartHttpServletRequest", "ServerHttpRequest", "ServerWebExchange"}
SOURCE_ANN = re.compile(r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|"
                        r"MatrixVariable|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|RequestPart|BeanParam)\b")
ENTRY_ANN = re.compile(r"@\w*Mapping\b|@(?:GET|POST|PUT|DELETE|PATCH)\b|@Path\b")
HOLDER = "holder"
HOLDER_SRC = {"getParameter", "getParameterValues", "getParameterMap", "getHeader", "getHeaders", "getQueryString",
              "getRequestURI", "getRequestURL", "getPathInfo", "getServletPath", "getCookies", "getInputStream",
              "getReader", "getPart", "getParts", "getBody", "getUrl", "getRemoteUser", "getPathTranslated",
              "getParameterNames", "getHeaderNames"}
SERVLET_ENTRY = {"doGet", "doPost", "doPut", "doDelete", "service", "doHead", "doOptions"}
SOURCE_CALL = re.compile(r"\.\s*(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|"
                         r"getRequestURI|getRequestURL|getPathInfo|getServletPath)\s*\(")

SANITIZERS: List[Tuple[re.Pattern, FrozenSet[str]]] = [
    (re.compile(r"\bhtmlEscape\w*\s*\(|\bescapeHtml\d?\s*\(|\bescapeXml\w*\s*\(|"
                r"\bEncode\s*\.\s*for\w+\s*\(|\bforHtml\w*\s*\(|\bforJavaScript\w*\s*\(|"
                r"\bencodeFor(?:HTML|JavaScript|HTMLAttribute)\w*\s*\(|\bescapeEcmaScript\s*\(|"
                r"\bJsoup\s*\.\s*clean\s*\(|\bescapeJava\s*\(|\bsanitizeHtml\w*\s*\(|"
                r"\bStringEscapeUtils\s*\.\s*escape\w+\s*\("), frozenset({XSS})),
    (re.compile(r"\b(?:Integer|Long|Short|Byte|Double|Float|BigDecimal|BigInteger)\s*\.\s*(?:parse\w+|valueOf)\s*\(|"
                r"\bBoolean\s*\.\s*parseBoolean\s*\(|\bUUID\s*\.\s*fromString\s*\(|\bnew\s+(?:BigDecimal|BigInteger)\s*\(|"
                r"\bLocalDate\s*\.\s*parse\s*\(|\bURLEncoder\s*\.\s*encode\s*\(|\bUriUtils\s*\.\s*encode\w*\s*\(|"
                r"\bPattern\s*\.\s*quote\s*\(|\bFilenameUtils\s*\.\s*getName\s*\(|\bshellEscape\w*\s*\("), ALL),
]
# Calls that return *stored data* (file contents, DB rows, repository entities): the value is not request-tainted
# (second-order / stored flows are out of scope, so these launder taint instead of inventing reflected flows).
LOADERS = re.compile(r"\bFiles\s*\.\s*(?:readString|readAllBytes|readAllLines|lines|newBufferedReader|newInputStream)\s*\(|"
                     r"\.\s*(?:getForObject|getForEntity|postForObject|postForEntity|exchange|retrieve|openStream)\s*\(|"
                     r"\.\s*(?:queryFor\w+|query|executeQuery|findBy\w*|findAll|findById|getResourceAsStream|readLine|readLines|readAllBytes)\s*\(|"
                     r"\bnew\s+(?:FileInputStream|FileReader|Scanner|BufferedReader|InputStreamReader)\s*\(")
QUOTE_STRIP = re.compile(r'''\.\s*replace(?:All)?\s*\(\s*"[^"]*'[^"]*"\s*,\s*""\s*\)''')
PATH_SANITIZE_SUFFIX = re.compile(r"\.\s*getFileName\s*\(\s*\)")
CHAR_ALLOWLIST_SANITIZE = re.compile(r"\.\s*replaceAll\s*\(\s*\"\[\^~+\]\+?\"\s*,\s*\"\"\s*\)")
CHAR_ALLOWLIST_TAIL = re.compile(r"\.\s*replaceAll\s*\(\s*\"\[\^[^\"]+\]\+?\"\s*,\s*\"[^\"\\]*\"\s*\)\s*$")

SQL_EXEC_NAMES = {"executeQuery", "executeUpdate", "execute", "executeLargeUpdate", "addBatch"}
JDBC_NAMES = {"query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "queryForStream", "update",
              "execute", "batchUpdate", "queryForLong", "queryForInt"}
JDBC_TYPES = re.compile(r"Jdbc|JdbcOperations|JdbcClient|Jdbi|DSLContext|DatabaseClient|SqlSession", re.I)
STMT_TYPES = re.compile(r"Statement")
JPA_NAMES = {"createQuery", "createNativeQuery", "createSQLQuery", "prepareStatement", "prepareCall"}
WRITER_TYPES = re.compile(r"^(?:PrintWriter|Writer|BufferedWriter|JspWriter|ServletOutputStream|OutputStreamWriter)$")

PATH_STRONG = [
    re.compile(r"\bnew\s+(?:FileInputStream|FileReader|FileOutputStream|FileWriter|RandomAccessFile|ClassPathResource|FileSystemResource|UrlResource)\s*\("),
    re.compile(r"\bFiles\s*\.\s*(?:readAllBytes|readString|readAllLines|newInputStream|newBufferedReader|newBufferedWriter|newOutputStream|write|writeString|copy|move|delete|deleteIfExists|list|walk|lines|createFile|createDirectories)\s*\("),
    re.compile(r"\.\s*getResourceAsStream\s*\("),
    re.compile(r"\bResourceUtils\s*\.\s*getFile\s*\("),
    re.compile(r"\b(?:resourceLoader|loader|classLoader)\s*\.\s*getResource\s*\("),
]
PATH_WEAK = [
    re.compile(r"\bnew\s+File\s*\("),
    re.compile(r"\b(?:Paths\s*\.\s*get|Path\s*\.\s*of)\s*\("),
]
CMD_PATTERNS = [
    re.compile(r"\bgetRuntime\s*\(\s*\)\s*\.\s*exec\s*\("),
    re.compile(r"\b(?:runtime|rt)\s*\.\s*exec\s*\("),
    re.compile(r"\bnew\s+ProcessBuilder\s*\("),
    re.compile(r"\b(?:builder|pb|processBuilder)\s*\.\s*command\s*\("),
    re.compile(r"\bCommandLine\s*\.\s*parse\s*\("),
    re.compile(r"\bnew\s+CommandLine\s*\("),
]
LOC = r"(?:\"Location\"|\"location\"|HttpHeaders\s*\.\s*LOCATION|LOCATION\w*)"
REDIR_PATTERNS = [
    (re.compile(r"\.\s*sendRedirect\s*\("), 0),
    (re.compile(r"\bnew\s+RedirectView\s*\("), 0),
    (re.compile(r"\.\s*(?:header|setHeader|addHeader|add|set|put)\s*\(\s*" + LOC + r"\s*,"), 1),
    (re.compile(r"\.\s*get\s*\(\s*" + LOC + r"\s*\)\s*\.\s*add\s*\("), 0),
    (re.compile(r"\.\s*location\s*\("), 0),
    (re.compile(r"\.\s*setLocation\s*\("), 0),
]
DENY_NAME = re.compile(r"(?i)deny|black|block|forbid|bad|reject|banned|invalid")
HTML_LIT = re.compile(r"<\s*[A-Za-z!/]")


def _lits(expr: str) -> str:
    return "".join(re.findall(r'"((?:\\.|[^"\\])*)"', expr))


# ------------------------------------------------------------------------------------------------ data model
class Param:
    def __init__(self, ann: str, typ: str, name: str):
        self.ann, self.typ, self.name = ann, typ, name


class Method:
    def __init__(self) -> None:
        self.file = ""
        self.cls = ""
        self.name = ""
        self.params: List[Param] = []
        self.ann = ""
        self.ret_type = ""
        self.start_line = 0
        self.end_line = 0
        self.body = ""
        self.body_m = ""
        self.body_line0 = 0
        self.is_entry = False
        self.is_rest = False
        self.html_produces = False
        self.cls_obj: Optional["ClassInfo"] = None


class ClassInfo:
    def __init__(self, name: str, file: str, start: int, end: int, header: str):
        self.name, self.file, self.start, self.end, self.header = name, file, start, end, header
        self.rest_only = False
        self.fields: Dict[str, str] = {}
        self.consts: Dict[str, str] = {}
        self.bases: List[str] = []
        self.methods: List[Method] = []


class FileInfo:
    def __init__(self, rel: str, text: str):
        self.rel = rel
        self.orig = blank_comments(text)
        self.masked = mask_text(text)
        self.lines_off: List[int] = []
        pos = 0
        for ln in text.split("\n"):
            self.lines_off.append(pos)
            pos += len(ln) + 1
        self.classes: List[ClassInfo] = []
        self.methods: List[Method] = []

    def line_of(self, off: int) -> int:
        lo, hi = 0, len(self.lines_off) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.lines_off[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1


_CLASS_RE = re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_]\w*)")
_CALLISH = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_FIELD_RE = re.compile(r"(?:^|[;{}]\s*)(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|private|protected|static|final|volatile|transient)\s+)*"
                       r"([A-Z][\w.]*(?:<[^;=(){}]*>)?)\s+([a-z_]\w*)\s*(?=[=;])")
_CONST_RE = re.compile(r"static\s+final\s+String\s+([A-Za-z_]\w*)\s*=\s*((?:\"(?:\\.|[^\"\\])*\"\s*\+?\s*)+);")


def parse_file(rel: str, text: str) -> FileInfo:
    fi = FileInfo(rel, text)
    m, o = fi.masked, fi.orig
    for cm in _CLASS_RE.finditer(m):
        before = m[:cm.start()].rstrip()
        if before.endswith("."):
            continue
        brace = m.find("{", cm.end())
        semi = m.find(";", cm.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        end = match_close(m, brace, "{", "}")
        if end < 0:
            continue
        ps = max(m.rfind(";", 0, cm.start()), m.rfind("}", 0, cm.start()), m.rfind("{", 0, cm.start()))
        header = o[ps + 1:brace]
        ci = ClassInfo(cm.group(1), rel, brace, end, header)
        ci.rest_only = bool(re.search(r"@\w*(?:RestController|ResponseBody)\b", header))
        for b in re.findall(r"(?:extends|implements)\s+([^{]+)", header):
            ci.bases += [x.strip().split("<")[0].split(".")[-1] for x in b.split(",") if x.strip()]
        body_m = m[brace:end]
        for fm in _FIELD_RE.finditer(body_m):
            ci.fields[fm.group(2)] = fm.group(1).split("<")[0].split(".")[-1]
        for km in _CONST_RE.finditer(o[brace:end]):
            ci.consts[km.group(1)] = "".join(re.findall(r'"((?:\\.|[^"\\])*)"', km.group(2)))
        fi.classes.append(ci)

    def innermost(off: int) -> Optional[ClassInfo]:
        best = None
        for c in fi.classes:
            if c.start <= off <= c.end and (best is None or (c.end - c.start) < (best.end - best.start)):
                best = c
        return best

    for cm in _CALLISH.finditer(m):
        name = cm.group(1)
        if name in KEYWORDS:
            continue
        before = m[:cm.start()].rstrip()
        if not before or before[-1] in ".@=(,?:;{}+-!&|*/%[":
            continue
        tail = re.search(r"([A-Za-z_]\w*)$", before)
        if tail and tail.group(1) in ("new", "return", "else", "throw", "case", "assert", "instanceof", "yield"):
            continue
        op = cm.end() - 1
        cl = match_close(m, op, "(", ")")
        if cl < 0:
            continue
        rm = re.match(r"\s*(?:throws\s+[\w.,\s<>]+?)?\s*\{", m[cl + 1:])
        if not rm:
            continue
        bo = cl + 1 + rm.end() - 1
        be = match_close(m, bo, "{", "}")
        if be < 0:
            continue
        cls = innermost(op)
        if cls is None:
            continue
        ps = max(m.rfind(";", 0, cm.start()), m.rfind("}", 0, cm.start()), m.rfind("{", 0, cm.start()))
        head = o[ps + 1:cm.start()]
        ann = " ".join(re.findall(r"@[\w.]+", head))
        meth = Method()
        meth.file, meth.cls, meth.name, meth.cls_obj = rel, cls.name, name, cls
        meth.ann = head
        hs = re.sub(r"@[\w.]+(?:\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))?", " ", head)
        hs = re.sub(r"\b(?:public|private|protected|static|final|synchronized|abstract|default|native)\b", " ", hs)
        meth.ret_type = hs.strip().split("<")[0].split(".")[-1] if hs.strip() else ""
        meth.start_line = fi.line_of(cm.start())
        meth.end_line = fi.line_of(be)
        meth.body = o[bo + 1:be]
        meth.body_m = m[bo + 1:be]
        meth.body_line0 = fi.line_of(bo + 1)
        pm_, po = m[op + 1:cl], o[op + 1:cl]
        for off, piece in split_top(pm_, ",", angle=True):
            ptxt = po[off:off + len(piece)].strip()
            if not ptxt:
                continue
            anns = " ".join(re.findall(r"@[\w.]+", ptxt))
            core = re.sub(r"@[\w.]+(?:\s*\((?:[^()]|\([^()]*\))*\))?", " ", ptxt)
            core = re.sub(r"\bfinal\b", " ", core).strip()
            mm = re.match(r"(.+?)\s+(?:\.\.\.\s*)?([A-Za-z_]\w*)$", core, re.S)
            if mm:
                meth.params.append(Param(anns, mm.group(1).strip(), mm.group(2)))
        meth.is_entry = bool(ENTRY_ANN.search(ann)) or (
            name in SERVLET_ENTRY and any(p.typ in REQ_HOLDER_TYPES for p in meth.params))
        meth.is_rest = bool(re.search(r"@\w*ResponseBody\b", ann)) or cls.rest_only or name in SERVLET_ENTRY
        meth.html_produces = bool(re.search(r"(?i)text[/_.]html|TEXT_HTML", head))
        fi.methods.append(meth)
        cls.methods.append(meth)
    return fi


# ----------------------------------------------------------------------------------------- validators
def validated_classes(v: str, text: str) -> FrozenSet[str]:
    """Which taint classes does a validator on variable `v` found in `text` neutralise?"""
    if not text or v not in text:
        return EMPTY
    e = re.escape(v)
    allp = [
        rf"\b{e}\s*\.\s*matches\s*\(",
        rf"\.\s*matcher\s*\(\s*{e}\s*\)\s*\.\s*matches\s*\(",
        rf"Pattern\s*\.\s*matches\s*\([^,]+,\s*{e}\s*\)",
        rf"\b{e}\s*\.\s*(?:equals|equalsIgnoreCase)\s*\(",
        rf"\.\s*(?:equals|equalsIgnoreCase)\s*\(\s*{e}\s*\)",
        rf"\b(?:is|has)(?:Valid|Safe|Allowed|Permitted|Whitelisted|Trusted|Legit)\w*\s*\([^)]*\b{e}\b",
        rf"\b(?:validate|verify|assertValid|assertSafe|ensureValid)\w*\s*\([^)]*\b{e}\b",
    ]
    for p in allp:
        if re.search(p, text):
            return ALL
    for cm in re.finditer(rf"([A-Za-z_][\w.()\"<>, /~]*?)\s*\.\s*(?:contains|containsKey|containsValue)\s*\(\s*{e}\s*(?:\.\s*\w+\s*\(\s*\))?\s*\)", text):
        recv = cm.group(1)
        if not DENY_NAME.search(recv) and recv.strip() != v:
            return ALL
    cls: Set[str] = set()
    if re.search(rf"if\s*\([^{{;]*\b{e}\s*\.\s*(?:contains|indexOf)\s*\(\s*\"[^\"]*[<>][^\"]*\"[^;{{]*\)\s*\{{?\s*(?:return|throw)", text):
        cls.add(XSS)
    if re.search(rf"\b{e}\s*\.\s*startsWith\s*\(\s*\"(?:/|https?://[^\"]+/)", text) or \
       re.search(rf"(?:URI\s*\.\s*create|new\s+URI)\s*\(\s*{e}\s*\)[^;]*\.\s*getHost\s*\(", text):
        cls.add(REDIR)
    if re.search(rf"\b{e}\b[^;]*\.\s*startsWith\s*\(", text) or (
            re.search(rf"\.\s*startsWith\s*\([^;]*\b{e}\b", text) and re.search(r"normalize|getCanonical|toRealPath|toAbsolutePath", text)):
        cls.add(PATH)
    return frozenset(cls)


class Env:
    def __init__(self, me: Method, taint: Dict[str, FrozenSet[str]]):
        self.me = me
        self.taint = taint
        self.types: Dict[str, str] = {}
        self.defline: Dict[str, int] = {}
        self.html: Set[str] = set()
        self.neutral: Set[str] = set()
        self.lits: Dict[str, str] = {}
        self.prefix: Dict[str, str] = {}
        self.derived: Dict[str, str] = {}
        self.fullval: Dict[str, FrozenSet[str]] = {}
        self.ret: Set[str] = set()


# ------------------------------------------------------------------------------------------------ analysis
class Analyzer:
    CALL_RE = re.compile(r"(?:(?<![\w.$])((?:this|[A-Za-z_]\w*)(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\.\s*)?(?<![\w$])([A-Za-z_]\w*)\s*\(")

    def __init__(self, files: List[FileInfo]):
        self.by_class: Dict[str, List[ClassInfo]] = {}
        self.by_method: Dict[str, List[Method]] = {}
        self.consts: Dict[str, str] = {}
        for fi in files:
            for c in fi.classes:
                self.by_class.setdefault(c.name, []).append(c)
                self.consts.update(c.consts)
            for me in fi.methods:
                self.by_method.setdefault(me.name, []).append(me)
        self.findings: Dict[Tuple[str, int, str, bool], CommonFinding] = {}
        self.memo: Set[Tuple] = set()
        self.model_sinks: List[Tuple[Method, int, str, str]] = []
        self.ret_summary: Dict[Tuple[str, int], FrozenSet[str]] = {}
        self.stored_types: Set[str] = set()

    # ---- expression taint
    def etaint(self, expr: str, env: Env, drop: Optional[Dict[str, FrozenSet[str]]] = None,
               nosan: bool = False) -> FrozenSet[str]:
        if not expr:
            return EMPTY
        m = mask_text(expr)
        lm = LOADERS.search(m)
        if lm:
            op = m.find("(", lm.start())
            cl = match_close(m, op, "(", ")") if op >= 0 else -1
            if cl >= 0:
                cut = lm.start()
                if m[cut] == ".":  # method-call loader: the whole receiver chain is stored data too
                    cut = self._receiver_start(m, cut)
                rest = expr[:cut] + " 0 " + expr[cl + 1:]
                extra: FrozenSet[str] = EMPTY
                if self.stored_types and re.match(r"\.\s*(?:findBy\w*|findAll|findById|query\w*|get\w+)\s*\(", m[lm.start():]):
                    rtype = env.types.get(re.sub(r"^this\s*\.\s*", "", self._receiver(m, lm.start())).split(".")[0].strip(), "")
                    if rtype in self.stored_types:
                        extra = frozenset({XSS})
                return self.etaint(rest, env, drop, nosan) | extra
        sub = self._summary_sub(expr, m, env, drop)
        if sub is not None:
            rest, add = sub
            return self.etaint(rest, env, drop, nosan) | add
        if nosan:
            return self._plain(m, env, drop, True)
        for pat, removed in SANITIZERS:
            sm = pat.search(m)
            if sm:
                op = m.find("(", sm.start())
                cl = match_close(m, op, "(", ")") if op >= 0 else -1
                if cl < 0:
                    cl = len(m) - 1
                rest = expr[:sm.start()] + " 0 " + expr[cl + 1:]
                if removed == frozenset({XSS}) and self._unquoted_ctx(expr, sm.start(), env):
                    removed = EMPTY  # HTML-escaping does not protect an unquoted attribute value
                return self.etaint(rest, env, drop) | (self.etaint(expr[op + 1:cl], env, drop) - removed)
        if PATH_SANITIZE_SUFFIX.search(m):
            return self._plain(m, env, drop) - {PATH}
        if CHAR_ALLOWLIST_TAIL.search(expr):
            return EMPTY  # value passed through an allow-list character filter (negated class replaced)
        tq = self._ternary(m)
        if tq:
            qi, ci = tq
            d2 = dict(drop or {})
            for v in env.taint:
                vc = validated_classes(v, expr[:qi])
                if vc:
                    d2[v] = d2.get(v, EMPTY) | vc
            return self.etaint(expr[qi + 1:ci], env, d2) | self.etaint(expr[ci + 1:], env, d2)
        return self._plain(m, env, drop)

    def _callee_ctx(self, callee: Method, targs: List[FrozenSet[str]]) -> Dict[str, FrozenSet[str]]:
        t0: Dict[str, FrozenSet[str]] = {}
        for i, cls in enumerate(targs):
            if cls and i < len(callee.params):
                p = callee.params[i]
                if p.typ.split("<")[0].split(".")[-1].strip() in NUMERIC_TYPES and not p.typ.endswith("]"):
                    continue
                t0[p.name] = cls
        return t0

    def _arg_taints(self, env: Env, args: List[str], drop) -> List[FrozenSet[str]]:
        targs = [self.etaint(a, env, drop) for a in args]
        for i, a in enumerate(args):
            av = a.strip()
            if av in env.taint and HOLDER in env.taint[av]:
                targs[i] = frozenset({HOLDER})
        return targs

    def _summary_sub(self, expr: str, m: str, env: Env, drop=None) -> Optional[Tuple[str, FrozenSet[str]]]:
        """Replace the first call to an analysed project method by that method's return-taint summary."""
        for cm in self.CALL_RE.finditer(m):
            name = cm.group(2)
            if name in KEYWORDS or name not in self.by_method:
                continue
            op = cm.end() - 1
            cl = match_close(m, op, "(", ")")
            if cl < 0:
                continue
            cargs = call_args(m, expr, op)
            cands = self.resolve(env.me, env, cm.group(1), name, len(cargs))
            if not cands:
                continue
            targs = self._arg_taints(env, cargs, drop)
            keys = []
            for c in cands:
                t0 = self._callee_ctx(c, targs)
                keys.append((c.file, c.start_line, tuple(sorted((k, tuple(sorted(v))) for k, v in t0.items()))))
            if any(k not in self.ret_summary for k in keys):
                continue
            add: Set[str] = set()
            for k in keys:
                add |= self.ret_summary[k]
            if XSS in add and re.search(r"->", m[op:cl]) and SANITIZERS[0][0].search(m[op:cl]):
                add.discard(XSS)  # a sanitising lambda is applied to the stored/loaded value
            return expr[:cm.start()] + " 0 " + expr[cl + 1:], frozenset(add)
        return None

    def _unquoted_ctx(self, expr: str, pos: int, env: Env) -> bool:
        pre = expr[:pos]
        if re.search(r'=\s*"\s*\+\s*$', pre):
            return True
        fm = None
        for fm in re.finditer(r"(?:\bformat|\bformatted)\s*\(", mask_text(pre)):
            pass
        if not fm:
            return False
        args = call_args(mask_text(expr), expr, fm.end() - 1)
        if len(args) < 2:
            return False
        off, idx = fm.end(), None
        for i, a in enumerate(args):
            at = expr.find(a, off - 1 if i == 0 else off)
            if at <= pos < at + len(a):
                idx = i
            off = at + len(a)
        if not idx:
            return False
        f0 = args[0].strip()
        lit = _lits(f0) if f0.startswith('"') else env.lits.get(f0) or self.consts.get(f0)
        if not lit:
            return False
        phs = [mm.start() for mm in re.finditer(r"%(?:\d+\$)?[sS]", lit)]
        return idx - 1 < len(phs) and bool(re.search(r"=\s*$", lit[:phs[idx - 1]]))

    @staticmethod
    def _ternary(m: str) -> Optional[Tuple[int, int]]:
        depth, q = 0, -1
        for i, ch in enumerate(m):
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "?" and depth == 0 and q < 0:
                q = i
            elif ch == ":" and depth == 0 and q >= 0:
                return q, i
        return None

    @staticmethod
    def _plain(m: str, env: Env, drop, nosan: bool = False) -> FrozenSet[str]:
        res: Set[str] = set()
        if SOURCE_CALL.search(m):
            res |= ALL
        m2 = re.sub(r"\bthis\s*\.\s*", "", m)
        for tm in re.finditer(r"(?<![\w.$])([A-Za-z_]\w*)\b(?!\s*\()", m2):
            v = tm.group(1)
            if nosan and v in env.neutral:
                res |= ALL
            if v in env.taint and HOLDER in env.taint[v]:
                am = re.match(r"\s*\.\s*(\w+)\s*\(", m2[tm.end():])
                if am and am.group(1) in HOLDER_SRC:
                    res |= ALL
                continue
            if v in env.taint:
                cls = env.taint[v]
                if drop and v in drop:
                    cls = cls - drop[v]
                res |= cls
        return frozenset(res)

    def _drop(self, env: Env, before: str) -> Dict[str, FrozenSet[str]]:
        d = {}
        for v in env.taint:
            full = env.fullval.get(v)
            if full is None:
                full = env.fullval[v] = validated_classes(v, env.me.body)
            if not full:
                continue  # never validated anywhere in the method -> never validated before this point either
            vc = validated_classes(v, before)
            if vc:
                d[v] = vc
        for dv, rv in env.derived.items():
            if dv in d and rv in env.taint:
                d[rv] = d.get(rv, EMPTY) | d[dv]
        return d

    # ---- entry
    def analyze_entry(self, me: Method) -> None:
        taint: Dict[str, FrozenSet[str]] = {}
        for p in me.params:
            base = p.typ.split("<")[0].split(".")[-1].strip()
            if base in NUMERIC_TYPES and not p.typ.endswith("]"):
                continue
            if base in REQ_HOLDER_TYPES and not SOURCE_ANN.search(p.ann):
                taint[p.name] = frozenset({HOLDER})
            elif SOURCE_ANN.search(p.ann):
                taint[p.name] = ALL
            elif base in NON_BOUND_TYPES or p.ann or me.name in SERVLET_ENTRY:
                continue
            else:
                taint[p.name] = ALL
        if taint:
            self.analyze(me, taint, 0, entry=True)

    def analyze(self, me: Method, taint0: Dict[str, FrozenSet[str]], depth: int, entry: bool = False) -> None:
        key = (me.file, me.start_line, tuple(sorted((k, tuple(sorted(v))) for k, v in taint0.items())), entry)
        if key in self.memo or depth > 4:
            return
        self.memo.add(key)
        env = Env(me, dict(taint0))
        if me.cls_obj:
            env.types.update(me.cls_obj.fields)
        for p in me.params:
            env.types[p.name] = p.typ.split("<")[0].split(".")[-1].strip()
        body, bm = me.body, me.body_m
        stmts: List[Tuple[int, str, str]] = []
        dp, start = 0, 0
        for i, ch in enumerate(bm):
            if ch in "([":
                dp += 1
            elif ch in ")]":
                dp -= 1
            elif dp <= 0 and ch in ";{}":
                seg = bm[start:i]
                if seg.strip():
                    lead = len(seg) - len(seg.lstrip())
                    stmts.append((start + lead, body[start + lead:i].rstrip(), bm[start + lead:i].rstrip()))
                start, dp = i + 1, 0
        seg = bm[start:]
        if seg.strip():
            lead = len(seg) - len(seg.lstrip())
            stmts.append((start + lead, body[start + lead:].rstrip(), bm[start + lead:].rstrip()))
        weak: List[CommonFinding] = []
        for off, st, stm in stmts:
            line = me.body_line0 + body.count("\n", 0, off)
            before = body[:off]
            if re.match(r"try\s*\(", stm):
                op = stm.find("(")
                cl = match_close(stm, op, "(", ")")
                end = cl if cl > 0 else len(st)
                for roff, piece in split_top(stm[op + 1:end], ";"):
                    if piece.strip():
                        po = st[op + 1 + roff:op + 1 + roff + len(piece)].strip()
                        self.stmt(env, me, po, mask_text(po), line, before, depth, entry, weak)
                continue
            mh = re.match(r"(?:else\s+)?(?:if|while|for|switch|catch|synchronized)\s*\(", stm)
            if mh:
                op = stm.find("(")
                cl = match_close(stm, op, "(", ")")
                if cl < 0:
                    continue
                head_o, head_m = st[op + 1:cl], stm[op + 1:cl]
                fe = re.match(r"(?:final\s+)?[\w<>\[\],.? ]+?\s+(\w+)\s*:\s*(.+)$", head_o, re.S)
                if fe and "for" in stm[:mh.end()]:
                    t = self.etaint(fe.group(2), env)
                    if t:
                        env.taint[fe.group(1)] = t
                else:
                    self.scan_sinks(env, me, head_o, head_m, line, before, depth, entry, weak)
                rest = st[cl + 1:].strip()
                if not rest:
                    continue
                st, stm = rest, mask_text(rest)
            elif re.match(r"else\b", stm):
                st, stm = st[4:].strip(), stm[4:].strip()
                if not st:
                    continue
            else:
                mc = re.match(r"(?:case\b[^:]*:|default\s*:)", stm)
                if mc:
                    st, stm = st[mc.end():].strip(), stm[mc.end():].strip()
                    if not st:
                        continue
            self.stmt(env, me, st, stm, line, before, depth, entry, weak)
        k_sum = (me.file, me.start_line, tuple(sorted((k, tuple(sorted(v))) for k, v in taint0.items())))
        self.ret_summary[k_sum] = self.ret_summary.get(k_sum, EMPTY) | frozenset(env.ret)
        for f in weak:
            strong = any(k[0] == f.file_path and k[2] == "CWE-22" and not k[3]
                         and me.start_line <= k[1] <= me.end_line and "PATHW" not in kk.finding_id
                         for k, kk in self.findings.items())
            if not strong:
                self._store(f)

    # ---- statement
    @staticmethod
    def _assign_eq(stm: str) -> int:
        d = 0
        for i, ch in enumerate(stm):
            if ch in "([{":
                d += 1
            elif ch in ")]}":
                d -= 1
            elif ch == "=" and d == 0:
                prev = stm[i - 1] if i else ""
                nxt = stm[i + 1] if i + 1 < len(stm) else ""
                if nxt == "=" or prev in "=!<>":
                    continue
                return i
        return -1

    def _html_expr(self, expr: str, env: Env) -> bool:
        if HTML_LIT.search(_lits(expr)):
            return True
        for tk in re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", mask_text(expr)):
            v = self.consts.get(tk)
            if v and HTML_LIT.search(v):
                return True
        return any(tk in env.html for tk in re.findall(r"[A-Za-z_]\w*", mask_text(expr)))

    def stmt(self, env: Env, me: Method, st: str, stm: str, line: int, before: str, depth: int, entry: bool,
             weak: list) -> None:
        # callees first: their return-taint summaries feed the expressions of this statement
        self.propagate(env, me, st, stm, before, depth)
        eq = self._assign_eq(stm)
        head = stm[:eq].strip() if eq > 0 else ""
        am = re.fullmatch(r"(?:final\s+)?(?:([A-Za-z_][\w.<>\[\],? ]*?)\s+)?([A-Za-z_]\w*(?:\s*\.\s*\w+)*)\s*[-+*]?", head) if head else None
        if am and not re.match(r"(?:return|throw|else|new)\b", stm):
            typ, lhs = am.group(1), am.group(2)
            rhs = st[eq + 1:].strip()
            root = re.split(r"\s*\.\s*", lhs)[0]
            if typ and typ.strip() not in KEYWORDS:
                env.types[root] = typ.strip().split("<")[0].split(".")[-1]
            if "getWriter" in rhs:
                env.types[root] = "PrintWriter"
            t = self.etaint(rhs, env)
            if t:
                env.taint[root] = env.taint.get(root, EMPTY) | t
                env.defline[root] = line
                dm = re.match(r"\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[.\[]", rhs)
                if dm and dm.group(1) in env.taint and dm.group(1) != root:
                    env.derived[root] = dm.group(1)
            elif typ and root in env.taint and "." not in lhs:
                del env.taint[root]
            if not t and self.etaint(rhs, env, nosan=True):
                env.neutral.add(root)
            elif t:
                env.neutral.discard(root)
            pm_ = re.match(r'\s*(?:new\s+StringBuil(?:der|fer)\s*\(\s*)?"((?:\\.|[^"\\])*)"', rhs)
            if pm_ and "." not in lhs:
                env.prefix[root] = pm_.group(1)
            elif root in env.prefix and typ:
                del env.prefix[root]
            if re.fullmatch(r'\s*"(?:\\.|[^"\\])*"(?:\s*\+\s*"(?:\\.|[^"\\])*")*\s*', rhs):
                env.lits[root] = _lits(rhs)
            if self._html_expr(rhs, env):
                env.html.add(root)
        else:
            # mutators anywhere in the statement (incl. inside lambda bodies): sb.append(x), list.add(x), obj.setX(x)
            for rm in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)\s*\.\s*(?:append|add|put|addAll|putAll|insert|offer|push|set[A-Z]\w*|concat)\s*\(", stm):
                root = rm.group(1)
                if root in ("this", "System"):
                    continue
                args = call_args(stm, st, rm.end() - 1)
                t = self.etaint(", ".join(args), env)
                if "->" in stm:
                    t = t | (self.etaint(st, env) & {XSS})
                if t:
                    env.taint[root] = env.taint.get(root, EMPTY) | t
                    env.defline[root] = line
                if self._html_expr(", ".join(args), env):
                    env.html.add(root)
        if re.match(r"return\b", stm):
            env.ret |= self.etaint(st[6:].strip(), env, self._drop(env, before))
            self.on_return(env, me, st[6:].strip(), line, before, entry)
        self.scan_sinks(env, me, st, stm, line, before, depth, entry, weak)

    # ---- emit
    def _mk(self, me: Method, rule: str, cwe: str, raw: str, vtype: str, sev: str, line: int, snippet: str,
            decoy: Optional[str] = None) -> CommonFinding:
        return CommonFinding(
            finding_id=f"SAST-JTAINT-{rule}-{me.file}-{line}",
            stage="SAST", scanner=SCANNER, cwe=canonicalize_cwe(cwe), raw_cwe=raw, vuln_type=vtype,
            severity=sev,  # type: ignore[arg-type]
            file_path=me.file, line=line, end_line=me.end_line, function_name=me.name,
            code_snippet=" ".join(snippet.split())[:300],
            is_safe_decoy=bool(decoy), suppression_reason=decoy,
            engines=[ENGINE_AST_TAINT] + ([ENGINE_DECOY] if decoy else []),
        )

    def _store(self, f: CommonFinding) -> None:
        k = (f.file_path or "", f.line or 0, f.cwe, f.is_safe_decoy)
        if k in self.findings:
            return
        if f.is_safe_decoy and (k[0], k[1], k[2], False) in self.findings:
            return
        if not f.is_safe_decoy:
            self.findings.pop((k[0], k[1], k[2], True), None)
        self.findings[k] = f

    def _report(self, env: Env, me: Method, cwecls: str, rule: str, cwe: str, raw: str, vtype: str, sev: str,
                line: int, snippet: str, arg_exprs: List[str], before: str, weak: Optional[list] = None,
                const_decoy: Optional[str] = None) -> None:
        drop = self._drop(env, before)
        raw_t: Set[str] = set()
        net_t: Set[str] = set()
        for a in arg_exprs:
            raw_t |= self.etaint(a, env, nosan=True)
            net_t |= self.etaint(a, env, drop)
        if cwecls == PATH and re.search(r"normalize|getCanonicalPath|toRealPath|toAbsolutePath", me.body) \
                and re.search(r"\.\s*startsWith\s*\(", me.body):
            net_t.discard(PATH)
        if cwecls in net_t:
            rline = line
            f = self._mk(me, rule, cwe, raw, vtype, sev, rline, snippet)
            if weak is not None:
                weak.append(f)
            else:
                self._store(f)
        elif cwecls in raw_t:
            self._store(self._mk(me, rule + "-SAFE", cwe, raw, vtype + " (guarded)", "INFO", line, snippet,
                                 decoy=f"{vtype}: tainted value neutralised by a validator / allow-list / sanitizer before the sink"))
        elif const_decoy:
            self._store(self._mk(me, rule + "-CONST", cwe, raw, vtype + " (constant)", "INFO", line, snippet, decoy=const_decoy))

    def on_return(self, env: Env, me: Method, expr: str, line: int, before: str, entry: bool) -> None:
        if not entry or not me.is_rest:
            return
        raw_t = self.etaint(expr, env, nosan=True)
        drop = self._drop(env, before)
        net = self.etaint(expr, env, drop)
        if any(XSS in c for c in drop.values()):
            net = net - {XSS}  # this handler rejects/validates markup in its input before responding
            raw_t = raw_t | {XSS}
        htmlish = self._html_expr(expr, env)
        textual = me.ret_type in ("String", "CharSequence") or bool(re.search(r"ResponseEntity\s*<\s*String\s*>", me.ann))
        if not (htmlish or me.html_produces or textual):
            return
        if XSS in net:
            self._store(self._mk(me, "XSS", "CWE-79", "CWE-79", "Cross-Site Scripting (reflected)", "HIGH", line, "return " + expr))
        elif XSS in raw_t and (htmlish or me.html_produces):
            self._store(self._mk(me, "XSS-SAFE", "CWE-79", "CWE-79", "XSS (output-encoded)", "INFO", line, "return " + expr,
                                 decoy="User value HTML-encoded (htmlEscape / escapeHtml4 / Encode.forHtml) or validated before being embedded in the response"))

    # ---- sinks
    @staticmethod
    def _receiver_start(stm: str, dot_idx: int) -> int:
        i, d = dot_idx, 0
        while i > 0:
            ch = stm[i - 1]
            if ch == ")":
                d += 1
            elif ch == "(":
                if d == 0:
                    break
                d -= 1
            elif d == 0 and not (ch.isalnum() or ch in "_.$"):
                break
            i -= 1
        return i

    @staticmethod
    def _receiver(stm: str, dot_idx: int) -> str:
        i, d = dot_idx, 0
        while i > 0:
            ch = stm[i - 1]
            if ch == ")":
                d += 1
            elif ch == "(":
                if d == 0:
                    break
                d -= 1
            elif d == 0 and not (ch.isalnum() or ch in "_.$"):
                break
            i -= 1
        return stm[i:dot_idx].strip()

    def _const_has(self, expr: str, regex: str) -> bool:
        for tk in re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", mask_text(expr)):
            v = self.consts.get(tk)
            if v and re.search(regex, v):
                return True
        return False

    def _host_controlled(self, tgt: str, env: Optional[Env] = None) -> bool:
        if env is not None:
            bare = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*(?:\.\s*toString\s*\(\s*\))?\s*", tgt)
            if bare and bare.group(1) in env.prefix:
                pre = env.prefix[bare.group(1)]
                return pre == "" or bool(re.fullmatch(r"(?:https?:)?//[^/]*", pre)) or pre in ("http:", "https:")
        t = re.sub(r"^\s*(?:URI\s*\.\s*create|new\s+URI)\s*\(\s*", "", tgt.strip())
        if t.startswith('"'):
            lit = re.match(r'"((?:\\.|[^"\\])*)"', t)
            s = lit.group(1) if lit else ""
            if s.startswith("redirect:"):
                s = s[len("redirect:"):]
            rest = t[lit.end():].strip() if lit else ""
            if not rest.startswith("+") and "%s" not in s:
                return False  # constant target
            return s == "" or bool(re.fullmatch(r"(?:https?:)?//[^/]*", s)) or s in ("http:", "https:") or (
                "%s" in s and s.startswith(("%s", "http://%s", "https://%s")))
        fm = re.search(r'format\(\s*"((?:\\.|[^"\\])*)"', t)
        if fm:
            return fm.group(1).startswith(("%s", "redirect:%s", "http://%s", "https://%s"))
        return True

    def scan_sinks(self, env: Env, me: Method, st: str, stm: str, line: int, before: str, depth: int, entry: bool,
                   weak: list) -> None:
        snippet = st
        base_line = line

        def L(cm) -> int:
            return base_line + st[:cm.start()].count("\n")

        for cm in re.finditer(r"\.\s*([A-Za-z_]\w*)\s*\(", stm):
            name = cm.group(1)
            recv = self._receiver(stm, cm.start())
            rtype = env.types.get(recv.split(".")[0].strip(), "") if recv else ""
            is_sql = False
            if name in SQL_EXEC_NAMES and (STMT_TYPES.search(rtype) or "createStatement" in recv):
                is_sql = True
            elif name in JDBC_NAMES and (JDBC_TYPES.search(rtype) or re.search(r"(?i)jdbc|namedtemplate", recv or "")):
                is_sql = True
            elif name in JPA_NAMES:
                is_sql = True
            if is_sql:
                args = call_args(stm, st, cm.end() - 1)
                if args:
                    has_q = bool(re.search(r'"[^"]*(?:\?|:\w+)[^"]*"', args[0])) or self._const_has(args[0], r"\?|:\w+")
                    self._report(env, me, SQL, "SQLI", "CWE-89", "CWE-89", "SQL Injection", "CRITICAL", L(cm), snippet,
                                 [args[0]], before,
                                 const_decoy="Constant SQL text with bound parameters (no tainted data in the query string)" if has_q else None)
        for pat in CMD_PATTERNS:
            for cm in pat.finditer(stm):
                args = call_args(stm, st, cm.end() - 1)
                if args:
                    self._report(env, me, CMD, "CMDI", "CWE-78", "CWE-77", "Command Injection", "CRITICAL", L(cm), snippet,
                                 [", ".join(args)], before,
                                 const_decoy="Command built only from constants - no request data reaches Runtime.exec / ProcessBuilder")
        for is_weak, pats in ((False, PATH_STRONG), (True, PATH_WEAK)):
            for pat in pats:
                for cm in pat.finditer(stm):
                    args = call_args(stm, st, cm.end() - 1)
                    if args:
                        self._report(env, me, PATH, "PATHW" if is_weak else "PATH", "CWE-22", "CWE-22", "Path Traversal",
                                     "HIGH", L(cm), snippet, args if is_weak else args[:2], before,
                                     weak=weak if is_weak else None)
        for pat, argi in REDIR_PATTERNS:
            for cm in pat.finditer(stm):
                args = call_args(stm, st, cm.end() - 1 if stm[cm.end() - 1] == "(" else stm.find("(", cm.start()))
                if len(args) > argi and self._host_controlled(args[argi], env):
                    self._report(env, me, REDIR, "REDIR", "CWE-601", "CWE-601", "Open Redirect", "MEDIUM", L(cm), snippet,
                                 [args[argi]], before)
        for rm in re.finditer(r'"redirect:', st):
            seg = st[rm.start():]
            if self._host_controlled(seg.split(",")[0] if "format" not in st else seg, env):
                self._report(env, me, REDIR, "REDIR", "CWE-601", "CWE-601", "Open Redirect", "MEDIUM", line, snippet, [seg], before)
        for cm in re.finditer(r"\.\s*(println|print|write|printf|append|format)\s*\(", stm):
            recv = self._receiver(stm, cm.start())
            rtype = env.types.get(recv.split(".")[0].strip(), "") if recv else ""
            if ("getWriter" in recv or "getOutputStream" in recv or WRITER_TYPES.search(rtype)) and "System" not in recv:
                args = call_args(stm, st, cm.end() - 1)
                if args:
                    self._report(env, me, XSS, "XSS", "CWE-79", "CWE-79", "Cross-Site Scripting (reflected)", "HIGH", line,
                                 snippet, [", ".join(args)], before)
        for cm in re.finditer(r"(?:this\s*\.\s*)?(\w+)\s*\.\s*(?:save|saveAll|saveAndFlush|insert|persist|merge)\s*\(", stm):
            rtype = env.types.get(cm.group(1), "")
            args = call_args(stm, st, cm.end() - 1)
            if rtype and args and XSS in self.etaint(args[0], env):
                self.stored_types.add(rtype)
        for cm in re.finditer(r"\.\s*(addAttribute|addObject)\s*\(\s*\"([\w.-]+)\"\s*,", st):
            args = call_args(stm, st, st.find("(", cm.start()))
            if len(args) >= 2 and XSS in self.etaint(args[1], env, self._drop(env, before)):
                self.model_sinks.append((me, line, cm.group(2), snippet))
        self.propagate(env, me, st, stm, before, depth)

    # ---- interprocedural
    def propagate(self, env: Env, me: Method, st: str, stm: str, before: str, depth: int) -> None:
        drop = self._drop(env, before)
        for cm in self.CALL_RE.finditer(stm):
            name = cm.group(2)
            if name in KEYWORDS or name not in self.by_method:
                continue
            args = call_args(stm, st, cm.end() - 1)
            targs = self._arg_taints(env, args, drop)
            if not any(targs):
                continue
            for callee in self.resolve(me, env, cm.group(1), name, len(args)):
                if callee is me:
                    continue
                t0 = self._callee_ctx(callee, targs)
                if t0:
                    self.analyze(callee, t0, depth + 1)

    def resolve(self, me: Method, env: Env, recv: Optional[str], name: str, nargs: int) -> List[Method]:
        cands = [c for c in self.by_method.get(name, []) if len(c.params) == nargs]
        if not cands:
            return []
        if not recv or recv.strip() == "this":
            same = [c for c in cands if c.cls == me.cls and c.file == me.file]
            if same:
                return same
            bases = set(me.cls_obj.bases) if me.cls_obj else set()
            return [c for c in cands if c.cls in bases]
        root = recv.split(".")[0].strip()
        typ = env.types.get(root) or (root if root[:1].isupper() else None)
        if not typ:
            return []
        out = [c for c in cands if c.cls == typ]
        if out:
            return out
        impls = {ci.name for lst in self.by_class.values() for ci in lst if typ in ci.bases}
        return [c for c in cands if c.cls in impls]


# --------------------------------------------------------------------------------------- templates
_TH_UTEXT = re.compile(r"th:utext\s*=\s*\"[^\"]*\$\{\s*(\w+)")
_TH_INLINE = re.compile(r"\[\(\s*\$\{\s*(\w+)")
_JSP_EL = re.compile(r"\$\{\s*(\w+)[^}]*\}")


def _template_refs(source_root: str) -> Dict[str, List[Tuple[str, int, str]]]:
    refs: Dict[str, List[Tuple[str, int, str]]] = {}
    for root, _, files in os.walk(source_root):
        norm = root.replace("\\", "/") + "/"
        if any(x in norm for x in ("/.git/", "/node_modules/", "/target/", "/build/")):
            continue
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in (".html", ".htm", ".jsp", ".ftl", ".vm"):
                continue
            p = os.path.join(root, fn)
            try:
                lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
            except OSError:
                continue
            rel = os.path.relpath(p, source_root).replace("\\", "/")
            for i, ln in enumerate(lines):
                for m in _TH_UTEXT.finditer(ln):
                    refs.setdefault(m.group(1), []).append((rel, i + 1, "th:utext"))
                for m in _TH_INLINE.finditer(ln):
                    refs.setdefault(m.group(1), []).append((rel, i + 1, "[( )]"))
                if ext == ".jsp" and "c:out" not in ln and "escapeXml" not in ln:
                    for m in _JSP_EL.finditer(ln):
                        if m.group(1) not in ("param", "header", "cookie", "pageContext"):
                            refs.setdefault(m.group(1), []).append((rel, i + 1, "JSP EL (unescaped)"))
    return refs


# ----------------------------------------------------------------------------------------- public API
def scan_java_project(source_root: str) -> Tuple[List[CommonFinding], List[CommonFinding]]:
    """Returns (active_findings, suppressed_decoys)."""
    files: List[FileInfo] = []
    for root, _, fnames in os.walk(source_root):
        norm = root.replace("\\", "/") + "/"
        if any(x in norm for x in ("/.git/", "/build/", "/src/test/", "/target/", "/node_modules/")):
            continue
        for fn in fnames:
            if not fn.endswith(".java"):
                continue
            p = os.path.join(root, fn)
            try:
                text = open(p, encoding="utf-8", errors="ignore").read()
                files.append(parse_file(os.path.relpath(p, source_root).replace("\\", "/"), text))
            except Exception:
                continue
    an = Analyzer(files)
    for _pass in range(2):
        before_types = set(an.stored_types)
        an.memo.clear()
        an.ret_summary.clear()
        for fi in files:
            for me in fi.methods:
                if me.is_entry:
                    try:
                        an.analyze_entry(me)
                    except RecursionError:
                        pass
        if _pass == 0 and an.stored_types == before_types:
            break  # no persistence sinks found: second (stored-flow) pass would change nothing
    if an.model_sinks:
        refs = _template_refs(source_root)
        for me, line, attr, snip in an.model_sinks:
            hits = refs.get(attr)
            if hits:
                an._store(an._mk(me, "XSS-TPL", "CWE-79", "CWE-79", "Cross-Site Scripting (unescaped template output)", "HIGH", line,
                                 f"{snip}   // rendered unescaped at {hits[0][0]}:{hits[0][1]} via {hits[0][2]}"))
    act = [f for f in an.findings.values() if not f.is_safe_decoy]
    sup = [f for f in an.findings.values() if f.is_safe_decoy]
    return act, sup
