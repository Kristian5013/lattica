#!/usr/bin/env python3
"""Lattica locale helpers: structure-merge the lupdate-skipped variants up to the
canonical en.ts, fill en.ts itself, and extract/patch the untranslated strings.

The .ts files are Qt Linguist XML. We treat each <message> keyed by
(context-name, source, optional comment) and copy translations across.
"""
import sys, os, re, json, glob
import xml.etree.ElementTree as ET

LOCALE = os.path.join(os.path.dirname(__file__), "..", "src", "qt", "locale")
LOCALE = os.path.abspath(LOCALE)

def parse(path):
    return ET.parse(path)

def msg_key(ctx_name, msg):
    src = msg.find("source")
    src = src.text if src is not None else ""
    cmt = msg.find("comment")
    cmt = cmt.text if cmt is not None else ""
    return (ctx_name, src or "", cmt or "")

def translations_map(tree):
    """key -> the <translation> element (cloned text), for finished translations only."""
    out = {}
    root = tree.getroot()
    for ctx in root.findall("context"):
        name_el = ctx.find("name")
        ctx_name = name_el.text if name_el is not None else ""
        for msg in ctx.findall("message"):
            tr = msg.find("translation")
            if tr is None:
                continue
            # finished = no type="unfinished" and has some text/numerusform text
            if tr.get("type") == "unfinished":
                continue
            out[msg_key(ctx_name, msg)] = tr
    return out

def cmd_merge_variants():
    """Bring lupdate-skipped variant .ts up to en.ts's 874-message structure,
    preserving each variant's existing translations; new messages -> unfinished."""
    en = parse(os.path.join(LOCALE, "lattica_en.ts"))
    variants = ["ast_ES","az@latin","cmn","hak","kk@latin","pam",
                "sr@ijekavianlatin","sr@latin","szl","uz@Cyrl","uz@Latn","ve","yue"]
    for code in variants:
        path = os.path.join(LOCALE, f"lattica_{code}.ts")
        if not os.path.exists(path):
            print(f"  SKIP missing {code}"); continue
        old = parse(path)
        old_lang = old.getroot().get("language")
        existing = translations_map(old)
        # Start from a fresh copy of en's structure, then graft existing translations
        new_tree = parse(os.path.join(LOCALE, "lattica_en.ts"))
        nr = new_tree.getroot()
        nr.set("language", old_lang or code)
        filled = 0; unfinished = 0
        for ctx in nr.findall("context"):
            cname = ctx.find("name")
            cname = cname.text if cname is not None else ""
            for msg in ctx.findall("message"):
                tr = msg.find("translation")
                key = msg_key(cname, msg)
                if key in existing:
                    # graft: replace translation element wholesale
                    src_tr = existing[key]
                    msg.remove(tr)
                    import copy
                    msg.append(copy.deepcopy(src_tr))
                    filled += 1
                else:
                    # mark unfinished, clear text
                    tr.set("type", "unfinished")
                    tr.text = ""
                    for nf in tr.findall("numerusform"):
                        nf.text = ""
                    unfinished += 1
        new_tree.write(path, encoding="utf-8", xml_declaration=True)
        print(f"  {code}: grafted {filled}, unfinished {unfinished}")

def cmd_fill_en():
    """English .ts: fill every unfinished translation with its source text."""
    path = os.path.join(LOCALE, "lattica_en.ts")
    tree = parse(path); root = tree.getroot()
    n = 0
    for ctx in root.findall("context"):
        for msg in ctx.findall("message"):
            tr = msg.find("translation")
            if tr is None or tr.get("type") != "unfinished":
                continue
            src = msg.find("source")
            src_txt = src.text if src is not None else ""
            if msg.get("numerus") == "yes":
                forms = tr.findall("numerusform")
                if not forms:
                    nf = ET.SubElement(tr, "numerusform"); forms=[nf]
                for nf in forms:
                    nf.text = src_txt
            else:
                tr.text = src_txt
            del tr.attrib["type"]
            n += 1
    tree.write(path, encoding="utf-8", xml_declaration=True)
    print(f"  en: filled {n} unfinished with source text")

def cmd_extract(ref="ru"):
    """Extract the ordered list of unfinished messages from a reference language
    into tools/new_strings.json: [{i, context, source, comment, numerus, nforms}]."""
    path = os.path.join(LOCALE, f"lattica_{ref}.ts")
    tree = parse(path); root = tree.getroot()
    items = []
    for ctx in root.findall("context"):
        cname = ctx.find("name"); cname = cname.text if cname is not None else ""
        for msg in ctx.findall("message"):
            tr = msg.find("translation")
            if tr is None or tr.get("type") != "unfinished":
                continue
            src = msg.find("source"); src = src.text if src is not None else ""
            cmt = msg.find("comment"); cmt = cmt.text if cmt is not None else ""
            xcm = msg.find("extracomment"); xcm = xcm.text if xcm is not None else ""
            numerus = msg.get("numerus") == "yes"
            nforms = len(tr.findall("numerusform")) if numerus else 0
            items.append({"i": len(items), "context": cname, "source": src,
                          "comment": cmt or "", "extracomment": xcm or "",
                          "numerus": numerus, "nforms": nforms})
    out = os.path.join(os.path.dirname(__file__), "new_strings.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=1)
    print(f"  extracted {len(items)} unfinished from {ref} -> {out}")

def cmd_verify():
    """Verify every updated language shares the same ordered unfinished source set."""
    ref = json.load(open(os.path.join(os.path.dirname(__file__),"new_strings.json"),encoding="utf-8"))
    ref_src = [(x["context"], x["source"]) for x in ref]
    mism = []
    for path in sorted(glob.glob(os.path.join(LOCALE, "lattica_*.ts"))):
        code = os.path.basename(path)[len("lattica_"):-3]
        if code == "en": continue
        tree = parse(path); root = tree.getroot()
        got = []
        for ctx in root.findall("context"):
            cname = ctx.find("name"); cname = cname.text if cname is not None else ""
            for msg in ctx.findall("message"):
                tr = msg.find("translation")
                if tr is None or tr.get("type") != "unfinished": continue
                src = msg.find("source"); src = src.text if src is not None else ""
                got.append((cname, src))
        status = "OK" if got == ref_src else f"DIFF ({len(got)} vs {len(ref_src)})"
        if got != ref_src: mism.append(code)
        print(f"  {code}: {status}")
    print("MISMATCH:", mism if mism else "none")

def cmd_patch(code):
    """Fill lattica_<code>.ts unfinished entries (in document order) from
    tools/trans/<code>.json (a JSON array of exactly len(unfinished) strings)."""
    tf = os.path.join(os.path.dirname(__file__), "trans", f"{code}.json")
    trans = json.load(open(tf, encoding="utf-8"))
    path = os.path.join(LOCALE, f"lattica_{code}.ts")
    tree = parse(path); root = tree.getroot()
    # collect unfinished translation elements in order
    slots = []
    for ctx in root.findall("context"):
        for msg in ctx.findall("message"):
            tr = msg.find("translation")
            if tr is None or tr.get("type") != "unfinished":
                continue
            slots.append((msg, tr))
    if len(slots) != len(trans):
        print(f"  {code}: COUNT MISMATCH ts={len(slots)} json={len(trans)} — SKIP"); return False
    n = 0
    for (msg, tr), t in zip(slots, trans):
        if not isinstance(t, str) or t == "":
            continue  # leave unfinished if empty
        if msg.get("numerus") == "yes":
            forms = tr.findall("numerusform")
            if not forms:
                ET.SubElement(tr, "numerusform"); forms = tr.findall("numerusform")
            for nf in forms:
                nf.text = t
        else:
            tr.text = t
        if "type" in tr.attrib:
            del tr.attrib["type"]
        n += 1
    tree.write(path, encoding="utf-8", xml_declaration=True)
    print(f"  {code}: patched {n}/{len(slots)}")
    return True

def cmd_patchall():
    ok = 0
    for tf in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "trans", "*.json"))):
        code = os.path.basename(tf)[:-5]
        if cmd_patch(code): ok += 1
    print(f"patched {ok} languages")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "patch":
        cmd_patch(sys.argv[2])
    else:
        {"merge": cmd_merge_variants, "fillen": cmd_fill_en,
         "extract": cmd_extract, "verify": cmd_verify,
         "patchall": cmd_patchall}.get(cmd, lambda: print("usage: merge|fillen|extract|verify|patch <code>|patchall"))()
