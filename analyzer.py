"""
OctaveDebug Static Analyzer
Rule-based Octave/MATLAB error detection and auto-correction engine.
No external API required.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class OctaveError:
    id: int
    line: Optional[int]
    type: str
    description: str
    solution: str
    severity: str  # 'error' | 'warning' | 'info'
    original_line: Optional[str] = None
    fixed_line: Optional[str] = None


@dataclass
class AnalysisResult:
    errors: List[OctaveError]
    corrected_code: str
    summary: str
    original_code: str


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def strip_comments(line: str) -> str:
    """Remove inline % comments, preserving strings."""
    result = []
    in_str = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "'" and not in_str:
            in_str = True
            result.append(c)
        elif c == "'" and in_str:
            in_str = False
            result.append(c)
        elif c == '%' and not in_str:
            break
        else:
            result.append(c)
        i += 1
    return ''.join(result)


def is_blank_or_comment(line: str) -> bool:
    s = line.strip()
    return s == '' or s.startswith('%')


def get_indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


# ─────────────────────────────────────────────
#  Individual rule checkers
# ─────────────────────────────────────────────

def check_zero_indexing(lines: List[str]) -> List[OctaveError]:
    errors = []
    pattern = re.compile(r'\b(\w+)\s*\(\s*0\s*[\),]')
    for i, line in enumerate(lines):
        code = strip_comments(line)
        m = pattern.search(code)
        if m:
            var = m.group(1)
            # Exclude function calls that legitimately take 0
            if var not in ('zeros', 'ones', 'false', 'true', 'mod', 'rem',
                           'bitand', 'bitor', 'bitxor', 'pow2', 'log2'):
                errors.append(OctaveError(
                    id=0, line=i + 1, type='Zero Indexing Error',
                    description=f"'{var}(0, ...)' uses 0 as an index. Octave (like MATLAB) uses 1-based indexing — the first element is at index 1, not 0.",
                    solution=f"Change '{var}(0)' to '{var}(1)' to access the first element. All Octave indices must be ≥ 1.",
                    severity='error',
                    original_line=line.rstrip(),
                    fixed_line=re.sub(r'(\b' + re.escape(var) + r'\s*\(\s*)0(\s*[\),])', r'\g<1>1\2', line.rstrip(), count=1)
                ))
    return errors


def check_printf_vs_fprintf(lines: List[str]) -> List[OctaveError]:
    errors = []
    pattern = re.compile(r'\bprintf\s*\(')
    for i, line in enumerate(lines):
        code = strip_comments(line)
        if pattern.search(code):
            fixed = re.sub(r'\bprintf\s*\(', 'fprintf(', line.rstrip(), count=1)
            errors.append(OctaveError(
                id=0, line=i + 1, type="Undefined Function 'printf'",
                description="'printf' is not a built-in Octave function. Octave uses 'fprintf' for formatted output (similar to C's printf).",
                solution="Replace 'printf(...)' with 'fprintf(...)'. To print to the console, use 'fprintf(stdout, ...)' or simply 'fprintf(...)'.",
                severity='error',
                original_line=line.rstrip(),
                fixed_line=fixed
            ))
    return errors


def check_disp_vs_print(lines: List[str]) -> List[OctaveError]:
    """Detect print() which is not an Octave function."""
    errors = []
    pattern = re.compile(r'\bprint\s*\(')
    for i, line in enumerate(lines):
        code = strip_comments(line)
        if pattern.search(code):
            # Extract the argument
            m = re.search(r'print\s*\((.+)\)', code)
            arg = m.group(1).strip() if m else '...'
            fixed = re.sub(r'\bprint\s*\(', 'disp(', line.rstrip(), count=1)
            errors.append(OctaveError(
                id=0, line=i + 1, type="Undefined Function 'print'",
                description="'print()' is not an Octave function. It is Python syntax. Octave uses 'disp()' for simple output or 'fprintf()' for formatted output.",
                solution=f"Replace 'print({arg})' with 'disp({arg})' for simple display, or use 'fprintf(\"%s\\n\", {arg})' for formatted output.",
                severity='error',
                original_line=line.rstrip(),
                fixed_line=fixed
            ))
    return errors


def check_assignment_in_condition(lines: List[str]) -> List[OctaveError]:
    errors = []
    # Match: if/while/elseif followed by something with = but not ==, !=, <=, >=
    pattern = re.compile(r'\b(if|while|elseif)\s*\(([^)]*)\)')
    single_eq = re.compile(r'(?<![=!<>])=(?!=)')
    for i, line in enumerate(lines):
        code = strip_comments(line)
        m = pattern.search(code)
        if m:
            condition = m.group(2)
            if single_eq.search(condition):
                keyword = m.group(1)
                fixed = re.sub(r'(?<![=!<>])=(?!=)', '==', line.rstrip())
                errors.append(OctaveError(
                    id=0, line=i + 1, type='Assignment in Condition (= instead of ==)',
                    description=f"Found '=' inside a '{keyword}' condition. In Octave, '=' is assignment and '==' is comparison. Using '=' in a condition assigns a value instead of comparing.",
                    solution=f"Replace '=' with '==' inside the '{keyword}(...)' condition to perform a comparison.",
                    severity='error',
                    original_line=line.rstrip(),
                    fixed_line=fixed
                ))
    return errors


def check_missing_semicolons(lines: List[str]) -> List[OctaveError]:
    """Warn about variable assignments without semicolons that will echo output."""
    errors = []
    # Match assignments or expressions not ending in ; or ...
    assign_pattern = re.compile(r'^\s*\w[\w.]*\s*=\s*.+[^;,\.\.\.]$')
    block_keywords = {'function', 'if', 'else', 'elseif', 'end', 'for',
                      'while', 'do', 'until', 'switch', 'case', 'otherwise',
                      'break', 'continue', 'return', 'endfunction', 'endif',
                      'endfor', 'endwhile'}
    for i, line in enumerate(lines):
        if is_blank_or_comment(line):
            continue
        code = strip_comments(line).rstrip()
        if not code:
            continue
        first_word = code.strip().split()[0].lower().rstrip('(') if code.strip() else ''
        if first_word in block_keywords:
            continue
        if assign_pattern.match(code) and not code.strip().endswith(('...', ',')):
            # Skip if it's a control structure or function def
            if '(' not in code.split('=')[0] or re.match(r'\s*\w+\s*=', code):
                fixed = line.rstrip() + ';'
                errors.append(OctaveError(
                    id=0, line=i + 1, type='Missing Semicolon (Unwanted Output)',
                    description=f"The assignment on line {i+1} does not end with a semicolon. In Octave, this causes the value to be printed to the console every time the line executes.",
                    solution="Add a semicolon ';' at the end of the line to suppress automatic output: change to '" + code.strip() + ";'",
                    severity='warning',
                    original_line=line.rstrip(),
                    fixed_line=fixed
                ))
    return errors


def check_end_statements(lines: List[str]) -> List[OctaveError]:
    """Check for unmatched block openers without corresponding 'end'."""
    errors = []
    openers = re.compile(r'^\s*(function|if|for|while|switch|do)\b')
    closers = re.compile(r'^\s*end\b|^\s*endfunction\b|^\s*endif\b|^\s*endfor\b|^\s*endwhile\b|^\s*until\b')
    
    stack = []
    for i, line in enumerate(lines):
        if is_blank_or_comment(line):
            continue
        code = strip_comments(line)
        om = openers.match(code)
        cm = closers.match(code)
        if om:
            keyword = om.group(1)
            stack.append((keyword, i + 1))
        if cm and stack:
            stack.pop()

    for keyword, lineno in stack:
        errors.append(OctaveError(
            id=0, line=lineno, type=f"Missing 'end' for '{keyword}' block",
            description=f"The '{keyword}' block starting at line {lineno} is never closed. Every 'function', 'if', 'for', 'while', and 'switch' block must have a matching 'end' (or 'endfunction', 'endif', etc.).",
            solution=f"Add 'end' (or 'end{keyword}') after the last statement inside the '{keyword}' block. Ensure proper nesting.",
            severity='error',
            original_line=None,
            fixed_line=None
        ))
    return errors


def check_division_by_zero(lines: List[str]) -> List[OctaveError]:
    errors = []
    pattern = re.compile(r'/\s*0\b(?!\.)') 
    for i, line in enumerate(lines):
        code = strip_comments(line)
        if pattern.search(code):
            errors.append(OctaveError(
                id=0, line=i + 1, type='Division by Zero',
                description=f"Line {i+1} divides by the literal 0. In Octave this produces Inf or NaN, which will silently corrupt downstream calculations.",
                solution="Check the divisor before dividing. Use 'if denominator ~= 0' guard, or replace with a small epsilon (e.g., 1e-10) if division by zero is a rounding concern.",
                severity='error',
                original_line=line.rstrip(),
                fixed_line=None
            ))
    return errors


def check_undefined_variables(lines: List[str]) -> List[OctaveError]:
    """Basic undefined variable detection — checks use before assignment."""
    errors = []
    defined = set()
    # Common Octave built-ins
    builtins = {
        'pi', 'e', 'inf', 'Inf', 'nan', 'NaN', 'true', 'false', 'eps',
        'i', 'j', 'ans', 'nargin', 'nargout', 'varargin', 'varargout',
        'stdin', 'stdout', 'stderr', 'end'
    }
    builtin_funcs = {
        'zeros', 'ones', 'eye', 'rand', 'randn', 'linspace', 'logspace',
        'size', 'length', 'numel', 'reshape', 'sum', 'prod', 'cumsum',
        'max', 'min', 'mean', 'std', 'var', 'abs', 'sqrt', 'exp', 'log',
        'log2', 'log10', 'sin', 'cos', 'tan', 'asin', 'acos', 'atan',
        'atan2', 'floor', 'ceil', 'round', 'mod', 'rem', 'sign',
        'disp', 'fprintf', 'printf', 'sprintf', 'input', 'error', 'warning',
        'assert', 'isempty', 'isnumeric', 'ischar', 'iscell', 'isstruct',
        'fieldnames', 'struct', 'cell', 'num2str', 'str2num', 'str2double',
        'strsplit', 'strjoin', 'strtrim', 'regexp', 'regexprep',
        'plot', 'figure', 'hold', 'xlabel', 'ylabel', 'title', 'legend',
        'grid', 'axis', 'xlim', 'ylim', 'subplot', 'close', 'clf',
        'sort', 'unique', 'find', 'any', 'all', 'diff', 'repmat',
        'horzcat', 'vertcat', 'cat', 'cell2mat', 'mat2cell',
        'fopen', 'fclose', 'fread', 'fwrite', 'fgets', 'fgetl',
        'tic', 'toc', 'clock', 'cputime', 'pause',
        'class', 'typecast', 'cast', 'int8', 'int16', 'int32', 'int64',
        'uint8', 'uint16', 'uint32', 'uint64', 'double', 'single', 'char',
        'magic', 'pascal', 'hilb', 'inv', 'det', 'trace', 'rank',
        'eig', 'svd', 'lu', 'qr', 'chol', 'norm', 'cross', 'dot',
        'kron', 'conv', 'deconv', 'fft', 'ifft', 'fftshift',
        'polyfit', 'polyval', 'roots', 'poly',
        'cellfun', 'arrayfun', 'structfun',
    }

    assign_pattern = re.compile(r'^\s*(\[[\w\s,]+\]|[\w.]+)\s*=\s*')
    for_pattern = re.compile(r'^\s*for\s+(\w+)\s*=')
    func_pattern = re.compile(r'^\s*function\s+(?:\[[\w\s,]+\]|[\w.]+)\s*=\s*\w+\s*\(([^)]*)\)')
    func_noret_pattern = re.compile(r'^\s*function\s+(\w+)\s*\(([^)]*)\)')

    for i, line in enumerate(lines):
        if is_blank_or_comment(line):
            continue
        code = strip_comments(line).strip()

        # Track function parameter definitions
        fm = func_pattern.match(code)
        if fm:
            params = [p.strip() for p in fm.group(1).split(',') if p.strip()]
            defined.update(params)
            continue
        fm2 = func_noret_pattern.match(code)
        if fm2:
            params = [p.strip() for p in fm2.group(2).split(',') if p.strip()]
            defined.update(params)
            continue

        # Track for-loop variables
        fm3 = for_pattern.match(code)
        if fm3:
            defined.add(fm3.group(1))

        # Track assignments
        am = assign_pattern.match(code)
        if am:
            lhs = am.group(1).strip()
            # Handle multiple return: [a, b] = ...
            if lhs.startswith('['):
                vars_in = re.findall(r'\w+', lhs)
                defined.update(vars_in)
            else:
                defined.add(lhs.split('.')[0])

        # Now check RHS for unknown identifiers
        rhs = code
        if am:
            eq_pos = code.index('=')
            rhs = code[eq_pos + 1:]

        tokens = re.findall(r'\b([a-zA-Z_]\w*)\b', rhs)
        for tok in tokens:
            if tok in builtins or tok in builtin_funcs or tok in defined:
                continue
            if tok in ('end', 'endfunction', 'endif', 'endfor', 'endwhile',
                       'if', 'else', 'elseif', 'for', 'while', 'do', 'until',
                       'switch', 'case', 'otherwise', 'break', 'continue',
                       'return', 'function', 'global', 'persistent', 'try',
                       'catch', 'unwind_protect', 'unwind_protect_cleanup'):
                continue
            # Heuristic: if followed by '(', it's a function call — skip
            idx = rhs.find(tok)
            after = rhs[idx + len(tok):].lstrip()
            if after.startswith('('):
                continue
            # Only report if it looks like a standalone variable usage
            # Avoid false positives by checking if it might be a function
            errors.append(OctaveError(
                id=0, line=i + 1, type='Potentially Undefined Variable',
                description=f"Variable '{tok}' is used on line {i + 1} but may not have been defined yet. This could cause an 'undefined symbol' runtime error in Octave.",
                solution=f"Make sure '{tok}' is assigned a value before line {i + 1}. Check for typos in the variable name, or declare it earlier in the code.",
                severity='warning',
                original_line=line.rstrip(),
                fixed_line=None
            ))
            # Add to defined to avoid duplicate reports
            defined.add(tok)

    return errors


def check_unmatched_brackets(lines: List[str]) -> List[OctaveError]:
    errors = []
    full_code = '\n'.join(lines)
    counts = {'(': 0, '[': 0}
    pairs = {'(': ')', '[': ']'}
    # Simple count approach
    for ch in full_code:
        if ch == '(':
            counts['('] += 1
        elif ch == ')':
            counts['('] -= 1
        elif ch == '[':
            counts['['] += 1
        elif ch == ']':
            counts['['] -= 1
    for opener, count in counts.items():
        if count > 0:
            errors.append(OctaveError(
                id=0, line=None, type=f"Unmatched '{opener}' Bracket",
                description=f"There are {count} more opening '{opener}' than closing '{pairs[opener]}' brackets in the code. This will cause a parse error.",
                solution=f"Add {count} closing '{pairs[opener]}' bracket(s) at the appropriate location(s). Check that every '{opener}' has a corresponding '{pairs[opener]}'.",
                severity='error',
                original_line=None,
                fixed_line=None
            ))
        elif count < 0:
            errors.append(OctaveError(
                id=0, line=None, type=f"Unmatched '{pairs[opener]}' Bracket",
                description=f"There are {abs(count)} more closing '{pairs[opener]}' than opening '{opener}' brackets. This will cause a parse error.",
                solution=f"Remove {abs(count)} extra '{pairs[opener]}' bracket(s), or add the missing '{opener}' bracket(s) at the correct location.",
                severity='error',
                original_line=None,
                fixed_line=None
            ))
    return errors


def check_string_quotes(lines: List[str]) -> List[OctaveError]:
    """Detect Python-style double-quote strings used where single-quote is expected."""
    errors = []
    # In Octave, double quotes are valid but behave differently (escape sequences)
    # Detect common mistake: double-quoted strings where variables are expected
    dq_pattern = re.compile(r'"[^"]*"')
    for i, line in enumerate(lines):
        code = strip_comments(line)
        # Only flag if there's a double-quoted string in a disp/fprintf context
        if re.search(r'\b(disp|fprintf|error|warning|sprintf)\s*\(', code):
            if dq_pattern.search(code):
                fixed = re.sub(r'"([^"]*)"', r"'\1'", line.rstrip())
                errors.append(OctaveError(
                    id=0, line=i + 1, type='Double-Quoted String (Potential Issue)',
                    description=f"Double-quoted strings in Octave support escape sequences (like \\n, \\t) which is fine, but single-quoted strings are the conventional Octave style for plain text. Mixing styles can cause confusion.",
                    solution="Use single quotes for plain strings: change \"text\" to 'text'. Use double quotes only when you need escape sequences like \\n.",
                    severity='info',
                    original_line=line.rstrip(),
                    fixed_line=fixed
                ))
    return errors


def check_wrong_negation(lines: List[str]) -> List[OctaveError]:
    """Detect ! used as logical negation (Python/C style) instead of ~."""
    errors = []
    # ! is actually valid in Octave, but ~ is the canonical style
    # Flag != which should be ~=
    neq_pattern = re.compile(r'!=')
    for i, line in enumerate(lines):
        code = strip_comments(line)
        if neq_pattern.search(code):
            fixed = re.sub(r'!=', '~=', line.rstrip())
            errors.append(OctaveError(
                id=0, line=i + 1, type="Non-Standard 'Not Equal' Operator (!=)",
                description="'!=' is C/Python syntax. While Octave accepts it, the standard Octave/MATLAB not-equal operator is '~='. Using '!=' may cause compatibility issues with MATLAB.",
                solution="Replace '!=' with '~=' for standard Octave/MATLAB compatibility.",
                severity='warning',
                original_line=line.rstrip(),
                fixed_line=fixed
            ))
    return errors


def check_colon_range_in_index(lines: List[str]) -> List[OctaveError]:
    """Detect common mistake of using length(x) as end index when 'end' keyword works."""
    errors = []
    pattern = re.compile(r'\(1\s*:\s*length\s*\(\s*(\w+)\s*\)\s*\)')
    for i, line in enumerate(lines):
        code = strip_comments(line)
        m = pattern.search(code)
        if m:
            var = m.group(1)
            fixed = re.sub(r'\(1\s*:\s*length\s*\(\s*\w+\s*\)\s*\)', '(:)', line.rstrip(), count=1)
            errors.append(OctaveError(
                id=0, line=i + 1, type="Verbose Index Range (Use 'end' or ':')",
                description=f"'1:length({var})' is a verbose way to index all elements. Octave provides the 'end' keyword and ':' shorthand for this.",
                solution=f"Replace '(1:length({var}))' with '(:)' to select all elements, or '(1:end)' for clarity.",
                severity='info',
                original_line=line.rstrip(),
                fixed_line=fixed
            ))
    return errors


def check_matrix_ops(lines: List[str]) -> List[OctaveError]:
    """Detect common matrix operation mistakes."""
    errors = []
    # a * b when element-wise .* might be intended — heuristic only
    # Detect ^  used instead of .^ for element-wise power
    pow_pattern = re.compile(r'(?<!\.)(\^)(?!\.)')
    for i, line in enumerate(lines):
        code = strip_comments(line)
        # Only flag if there's an array/vector context (has colon or end or [)
        if ('[' in code or ':' in code) and pow_pattern.search(code):
            errors.append(OctaveError(
                id=0, line=i + 1, type="Possible Matrix Power vs Element-wise Power",
                description=f"'^' performs matrix exponentiation. If you want element-wise power (each element raised to a power), use '.^' instead.",
                solution="Use '.^' for element-wise exponentiation (e.g., 'x.^2') and '^' only for matrix power (e.g., 'A^2' for A*A).",
                severity='warning',
                original_line=line.rstrip(),
                fixed_line=re.sub(r'(?<!\.)(\^)', '.^', line.rstrip())
            ))
    return errors


# ─────────────────────────────────────────────
#  Auto-correction engine
# ─────────────────────────────────────────────

def apply_corrections(lines: List[str], errors: List[OctaveError]) -> List[str]:
    """Apply all auto-fixable corrections to the code lines."""
    corrected = list(lines)
    # Build a map of line -> list of errors with fixes
    line_fixes = {}
    for e in errors:
        if e.line and e.fixed_line is not None:
            line_fixes.setdefault(e.line, []).append(e)

    for lineno, errs in line_fixes.items():
        # Apply the last applicable fix for that line
        # (fixes may conflict; take the most impactful)
        best = errs[-1]
        corrected[lineno - 1] = best.fixed_line
    
    # Handle missing end statements
    missing_ends = [e for e in errors if 'Missing' in e.type and "'end'" in e.type]
    if missing_ends:
        corrected.append('end')
    
    return corrected


# ─────────────────────────────────────────────
#  Main analysis function
# ─────────────────────────────────────────────

def analyze(code: str) -> AnalysisResult:
    lines = code.split('\n')
    all_errors: List[OctaveError] = []

    checkers = [
        check_zero_indexing,
        check_printf_vs_fprintf,
        check_disp_vs_print,
        check_assignment_in_condition,
        check_missing_semicolons,
        check_end_statements,
        check_division_by_zero,
        check_unmatched_brackets,
        check_string_quotes,
        check_wrong_negation,
        check_colon_range_in_index,
        check_matrix_ops,
        check_undefined_variables,  # Run last (most prone to false positives)
    ]

    for checker in checkers:
        try:
            found = checker(lines)
            all_errors.extend(found)
        except Exception:
            pass  # Never crash on a bad checker

    # Deduplicate by (line, type)
    seen = set()
    unique_errors = []
    for e in all_errors:
        key = (e.line, e.type)
        if key not in seen:
            seen.add(key)
            unique_errors.append(e)

    # Assign sequential IDs and sort by line
    unique_errors.sort(key=lambda e: (e.line or 9999, e.type))
    for idx, e in enumerate(unique_errors, 1):
        e.id = idx

    # Auto-correct
    corrected_lines = apply_corrections(lines, unique_errors)
    corrected_code = '\n'.join(corrected_lines)

    # Build summary
    n = len(unique_errors)
    err_count = sum(1 for e in unique_errors if e.severity == 'error')
    warn_count = sum(1 for e in unique_errors if e.severity == 'warning')
    info_count = sum(1 for e in unique_errors if e.severity == 'info')

    if n == 0:
        summary = "✓ No errors detected. The code appears syntactically and structurally correct."
    else:
        parts = []
        if err_count:
            parts.append(f"{err_count} error{'s' if err_count > 1 else ''}")
        if warn_count:
            parts.append(f"{warn_count} warning{'s' if warn_count > 1 else ''}")
        if info_count:
            parts.append(f"{info_count} suggestion{'s' if info_count > 1 else ''}")
        summary = f"Found {' and '.join(parts)} in your Octave code. Auto-corrections applied where possible."

    return AnalysisResult(
        errors=unique_errors,
        corrected_code=corrected_code,
        summary=summary,
        original_code=code
    )
