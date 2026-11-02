#!/usr/bin/env python3
"""
Lab 11 - Find methods that are CALLED but never DEFINED.

Why this matters for security code
  A function like  self._verify_attestation(...)  that is called but never written will
  crash with an AttributeError the moment that code path runs. Worse, if the call sits
  inside a try/except, the crash can be swallowed and the check silently never happens.
  A security check that does not exist is the same as no check.

How it works
  It reads Python files with the 'ast' module (Python's own code reader). For every class it
  collects (1) the names of methods the class defines, and (2) every  self.something(...)  call.
  Any called name that is not defined in the class (or in a base class defined in the same file)
  is reported.

Limits (read these)
  * It only checks  self.name(...)  calls inside a class, within one file.
  * A method could come from a base class in another file, or be added dynamically. Treat each
    result as 'go and look', not as a verdict.

Usage:
    python3 11_undefined_calls.py path/to/file_or_folder
"""
import ast
import os
import sys


def check_file(path):
    try:
        tree = ast.parse(open(path, encoding='utf-8', errors='replace').read(), filename=path)
    except SyntaxError as e:
        print(f'{path}: cannot parse ({e})')
        return 0
    classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}

    def defined(cls, seen=()):
        names = set()
        for item in cls.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(item.name)
            elif isinstance(item, ast.Assign):
                names |= {t.id for t in item.targets if isinstance(t, ast.Name)}
        # attributes assigned as self.x = ... (could be callables)
        for node in ast.walk(cls):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == 'self':
                        names.add(t.attr)
        for b in cls.bases:                       # follow base classes defined in this same file
            if isinstance(b, ast.Name) and b.id in classes and b.id not in seen:
                names |= defined(classes[b.id], seen + (cls.name,))
        return names

    problems = 0
    for cname, cls in classes.items():
        have = defined(cls)
        missing = {}
        for node in ast.walk(cls):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'self'):
                if node.func.attr not in have:
                    missing.setdefault(node.func.attr, []).append(node.lineno)
        for name, lines in sorted(missing.items()):
            problems += 1
            print(f'{path}: class {cname}: self.{name}() is called at line(s) {lines} but never defined')
    return problems


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    files = []
    if os.path.isfile(target):
        files = [target]
    else:
        for d, dirs, fs in os.walk(target):
            dirs[:] = [x for x in dirs if x not in ('.git', '__pycache__', 'node_modules', 'venv', '.venv')]
            files += [os.path.join(d, f) for f in fs if f.endswith('.py')]
    total = sum(check_file(f) for f in files)
    print(f'\nChecked {len(files)} file(s): {total} possible missing method(s).')
    print('Each one is a place to go and look. Is the method defined somewhere else, or is that code path broken?')


if __name__ == '__main__':
    main()
