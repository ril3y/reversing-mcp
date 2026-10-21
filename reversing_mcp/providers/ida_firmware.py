"""Provider-owned IDAPython recipes for firmware database setup."""

from __future__ import annotations


def build_arm_setup_script(
    *,
    base: str = "",
    thumb: bool = True,
    bits: int = 32,
    seed_prologues: bool = True,
    analyze: bool = True,
) -> str:
    """Build the deterministic ARM firmware setup recipe used by IDA."""
    if bits not in {32, 64}:
        raise ValueError("bits must be 32 or 64")
    base_expr = "None" if not base else str(int(base, 16))
    settings = (
        f"BASE={base_expr}; THUMB={bool(thumb)}; BITS={bits}; "
        f"SEED={bool(seed_prologues)}; ANALYZE={bool(analyze)}\n"
    )
    return (
        "import ida_segment, ida_idp, ida_segregs, ida_bytes, ida_ua, "
        "ida_funcs, ida_auto, idaapi, struct, re\n"
        + settings
        + r"""steps=[]
seg=ida_segment.get_first_seg()
seg.bitness = 1 if BITS==32 else 2
seg.update()
steps.append("bitness=%d"%BITS)
cur=seg.start_ea; base=BASE
if base is None:
    h=ida_bytes.get_bytes(cur,0x140) or b""
    gi=h.find(b"FILE_INFO")
    if gi>=0 and gi+36<=len(h):
        la=struct.unpack("<I",h[gi+20:gi+24])[0]
        co=struct.unpack("<I",h[gi+32:gi+36])[0]
        base=la-co; steps.append("GFH load=%#x content=%#x -> base=%#x"%(la,co,base))
    else:
        base=cur; steps.append("no GFH; base kept")
delta=base-cur
if delta:
    ida_segment.rebase_program(delta, ida_segment.MSF_FIXONCE)
    seg=ida_segment.get_first_seg()
    steps.append("rebased %+#x"%delta)
treg=ida_idp.str2reg("T")
if treg>=0:
    ida_segregs.set_default_sreg_value(seg, treg, 1 if THUMB else 0)
    steps.append("default T=%d"%(1 if THUMB else 0))
created=0
if SEED and treg>=0:
    data=ida_bytes.get_bytes(seg.start_ea, seg.size()) or b""
    for m in re.finditer(rb"\x2d\xe9", data):
        fa=seg.start_ea+m.start()
        if (fa & 1) or idaapi.is_code(ida_bytes.get_flags(fa)): continue
        ida_segregs.split_sreg_range(
            fa, treg, 1 if THUMB else 0, ida_segregs.SR_user, True)
        if ida_ua.create_insn(fa) and ida_funcs.add_func(fa): created+=1
        if created>6000: break
    steps.append("seeded %d prologues"%created)
if ANALYZE:
    ida_auto.plan_range(seg.start_ea, seg.end_ea)
    ida_auto.auto_wait()
    steps.append("analyzed")
_result={
    "base":hex(base), "bitness":seg.bitness, "thumb":THUMB,
    "funcs":idaapi.get_func_qty(), "steps":steps}
"""
    )
