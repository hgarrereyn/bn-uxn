from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LowLevelILLabel, LowLevelILFunction

# binary ninja text helpers
def tI(x): return InstructionTextToken(InstructionTextTokenType.InstructionToken, x)
def tR(x): return InstructionTextToken(InstructionTextTokenType.RegisterToken, x)
def tS(x): return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, x)
def tM(x): return InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, x)
def tE(x): return InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, x)
def tA(x,d): return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, x, d)
def tT(x): return InstructionTextToken(InstructionTextTokenType.TextToken, x)
def tN(x,d): return InstructionTextToken(InstructionTextTokenType.IntegerToken, x, d)

REGS = [
    'sp', 'tmp'
]

sp = lambda il: il.reg(2, 'sp')
subi = lambda v: lambda il: il.set_reg(2, 'sp', il.add(2, sp(il), il.const(2, v)))

def il_branch(il: LowLevelILFunction, cond, tdest, fdest, adjust=0):
    t_final = il.get_label_for_address(Architecture['uxn:uxn'], tdest)
    if t_final is None:
        t_final = LowLevelILLabel()
        il.mark_label(t_final)
        il.append(il.jump(il.const_pointer(2, tdest)))

    t_target = LowLevelILLabel()
    f_target = LowLevelILLabel()

    il.append(il.if_expr(cond, t_target, f_target))

    il.mark_label(t_target)
    il.append(subi(adjust)(il))
    il.append(il.goto(t_final))

    il.mark_label(f_target)
    il.append(subi(adjust)(il))


def jump_fixup(il: LowLevelILFunction, target, adjust=0, is_call=False):
    t_final = LowLevelILLabel()
    il.append(il.set_reg(2, 'tmp', il.zero_extend(2, target)))
    il.append(subi(adjust)(il))
    il.append(il.goto(t_final))

    il.mark_label(t_final)
    if is_call:
        il.append(il.call(il.reg(2, 'tmp')))
    else:
        il.append(il.jump(il.reg(2, 'tmp')))


def decode(dat, addr):
    if len(dat) < 1:
        return None

    ins = dat[0]
    # k = ins & 0x80 ? 0xff : 0;
    # s = ins & 0x40 ? &u->rst : &u->wst;
    opc = (0 - (ins >> 5)) & 0xff if ((ins & 0x1f) == 0) else ins & 0x3f

    # [ . ][ . ][ . ][ L ][ N ][ T ] <
    # [ . ][ . ][ . ][   H2   ][ T ] <
    # [   L2   ][   N2   ][   T2   ] <

    zT = lambda il: il.load(1, il.add(2, sp(il), il.const(2, 0)))
    zN = lambda il: il.load(1, il.add(2, sp(il), il.const(2, 1)))
    zL = lambda il: il.load(1, il.add(2, sp(il), il.const(2, 2)))
    zH2 = lambda il: il.load(2, il.add(2, sp(il), il.const(2, 1)))
    zT2 = lambda il: il.load(2, il.add(2, sp(il), il.const(2, 0)))
    zN2 = lambda il: il.load(2, il.add(2, sp(il), il.const(2, 2)))
    zL2 = lambda il: il.load(2, il.add(2, sp(il), il.const(2, 4)))

    x = opc & 0x20
    q = '2' if x else ''

    put = lambda il, off, v: il.store(1, il.add(2, sp(il), il.const(2, off)), v)
    put2 = lambda il, off, v: il.store(2, il.add(2, sp(il), il.const(2, off)), v)

    # print(hex(addr), hex(opc))

    # r = ins & 0x40
    # if r:
    #     print('---', hex(addr), hex(opc))

    k = ins & 0x80

    alloc = (lambda size: lambda il: subi(-size)(il)) if k else (lambda size: lambda il: il.nop())

    if len(dat) >= 4 and dat[0] == 0x5a and dat[1] == 0x5a:
        v_target = int.from_bytes(dat[2:4], 'big')
        return (
            [tI('direct')],
            InstructionInfo(length=4),
            lambda il: il.call(il.const_pointer(2, v_target))
        )

    match opc:
        case 0x00:
            info = InstructionInfo(length=1)
            info.add_branch(BranchType.ExceptionBranch)
            return (
                [tI('brk')],
                info,
                lambda il: il.trap(0)
            )
        case 0xff:
            v_true = addr + 3 + int.from_bytes(dat[1:3], 'big', signed=True)
            v_false = addr + 3
            # print(hex(addr), dat[1:3].hex(), hex(v_true))
            info = InstructionInfo(length=3)
            info.add_branch(BranchType.TrueBranch, v_true)
            info.add_branch(BranchType.FalseBranch, v_false)

            cond = lambda il: il.compare_not_equal(1, zT(il), il.const(1, 0))

            return (
                [tI('jci'), tS(' '), tA(hex(v_true), v_true)],
                info,
                [
                    lambda il: il_branch(il, cond(il), v_true, v_false, adjust=1)
                ]
            )
        case 0xfe:
            v_target = addr + 3 + int.from_bytes(dat[1:3], 'big', signed=True)
            info = InstructionInfo(length=3)
            info.add_branch(BranchType.UnconditionalBranch, v_target)
            return (
                [tI('jmi'), tS(' '), tA(hex(v_target), v_target)],
                info,
                lambda il: il.jump(il.const_pointer(2, v_target))
            )
        case 0xfd:
            v_target = addr + 3 + int.from_bytes(dat[1:3], 'big', signed=True)
            info = InstructionInfo(length=3)
            info.add_branch(BranchType.CallDestination, v_target)
            return (
                [tI('jsi'), tS(' '), tA(hex(v_target), v_target)],
                info,
                lambda il: il.call(il.const_pointer(2, v_target))
            )
        case 0xfb:
            val = int.from_bytes(dat[1:3], 'big')
            return (
                [tI('#'), tN(hex(val), val)],
                InstructionInfo(length=3),
                lambda il: il.push(2, il.const(2, val))
            )
        case 0xfc:
            val = dat[1]
            return (
                [tI('#'), tN(hex(val), val)],
                InstructionInfo(length=2),
                lambda il: il.push(1, il.const(1, val))
            )
        
        case 0xf9:
            val = int.from_bytes(dat[1:3], 'big')
            return (
                [tI('r#'), tN(hex(val), val)],
                InstructionInfo(length=3),
                # lambda il: il.push(2, il.const(2, val))
                lambda il: il.nop()
            )
        case 0xfa:
            val = dat[1]
            return (
                [tI('r#'), tN(hex(val), val)],
                InstructionInfo(length=2),
                # lambda il: il.push(1, il.const(1, val))
                lambda il: il.nop()
            )

        case 0x01:
            return (
                [tI('inc')],
                InstructionInfo(length=1),
                lambda il: put(il, 0, il.add(1, zT(il), il.const(1, 1))),
            )
        case 0x21:
            return (
                [tI('inc2')],
                InstructionInfo(length=1),
                lambda il: put2(il, 0, il.add(2, zT2(il), il.const(2, 1))),
            )
        case 0x02:
            return (
                [tI('pop')],
                InstructionInfo(length=1),
                subi(1)
            )
        case 0x22:
            return (
                [tI('pop2')],
                InstructionInfo(length=1),
                subi(2)
            )
        case 0x03:
            return (
                [tI('nip')],
                InstructionInfo(length=1),
                [
                    lambda il: put(il, 1, zT(il)),
                    subi(1)
                ]
            )
        case 0x23:
            return (
                [tI('nip2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(il, 2, zT2(il)),
                    subi(2)
                ]
            )
        case 0x04:
            return (
                [tI('swp')],
                InstructionInfo(length=1),
                [
                    lambda il: il.set_reg(1, 'tmp', zT(il)),
                    lambda il: put(il, 0, zN(il)),
                    lambda il: put(il, 1, il.reg(1, 'tmp')),
                ]
            )
        case 0x24:
            return (
                [tI('swp2')],
                InstructionInfo(length=1),
                [
                    lambda il: il.set_reg(2, 'tmp', zT2(il)),
                    lambda il: put2(il, 0, zN2(il)),
                    lambda il: put2(il, 2, il.reg(2, 'tmp')),
                ]
            )
        case 0x05:
            return (
                [tI('rot')],
                InstructionInfo(length=1),
                [
                    lambda il: il.set_reg(1, 'tmp', zT(il)),
                    lambda il: put(il, 0, zN(il)),
                    lambda il: put(il, 1, zL(il)),
                    lambda il: put(il, 2, il.reg(1, 'tmp')),
                ]
            )
        case 0x25:
            return (
                [tI('rot2')],
                InstructionInfo(length=1),
                [
                    lambda il: il.set_reg(2, 'tmp', zT2(il)),
                    lambda il: put2(il, 0, zN2(il)),
                    lambda il: put2(il, 2, zL2(il)),
                    lambda il: put2(il, 4, il.reg(2, 'tmp')),
                ]
            )
        case 0x06:
            return (
                [tI('dup')],
                InstructionInfo(length=1),
                lambda il: il.push(1, zT(il))
            )
        case 0x26:
            return (
                [tI('dup2')],
                InstructionInfo(length=1),
                lambda il: il.push(2, zT2(il))
            )
        case 0x07:
            return (
                [tI('ovr')],
                InstructionInfo(length=1),
                [
                    lambda il: il.push(1, zN(il)),
                ]
            )
        case 0x27:
            return (
                [tI('ovr2')],
                InstructionInfo(length=1),
                [
                    lambda il: il.push(2, zN2(il)),
                ]
            )
        case 0x08:
            return (
                [tI('eq')],
                InstructionInfo(length=1),
                [
                    lambda il: put(il, 1, il.compare_equal(1, zT(il), zN(il))),
                    subi(1)
                ]
            )
        case 0x28:
            return (
                [tI('eq2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(il, 3, il.compare_equal(1, zT2(il), zN2(il))),
                    subi(3)
                ]
            )
        case 0x09:
            return (
                [tI('neq')],
                InstructionInfo(length=1),
                [
                    lambda il: put(il, 1, il.compare_not_equal(1, zT(il), zN(il))),
                    subi(1)
                ]
            )
        case 0x29:
            return (
                [tI('neq2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(il, 3, il.compare_not_equal(1, zT2(il), zN2(il))),
                    subi(3)
                ]
            )
        case 0x0a:
            return (
                [tI('gth')],
                InstructionInfo(length=1),
                [
                    lambda il: put(il, 1, il.compare_signed_greater_than(1, zT(il), zN(il))),
                    subi(1)
                ]
            )
        case 0x2a:
            return (
                [tI('gth2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(il, 3, il.compare_signed_greater_than(1, zT2(il), zN2(il))),
                    subi(3)
                ]
            )
        case 0x0b:
            return (
                [tI('lth')],
                InstructionInfo(length=1),
                [
                    lambda il: put(il, 1, il.compare_signed_less_than(1, zT(il), zN(il))),
                    subi(1)
                ]
            )
        case 0x2b:
            return (
                [tI('lth2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(il, 3, il.compare_signed_less_than(1, zT2(il), zN2(il))),
                    subi(3)
                ]
            )
        case 0x0c:
            target = lambda il: il.add(2, il.const_pointer(2, addr), il.sign_extend(2, zT(il)))
            info = InstructionInfo(length=1)
            info.add_branch(BranchType.UnconditionalBranch, target)
            return (
                [tI('jmp')],
                info,
                lambda il: jump_fixup(il, target(il), adjust=1)
            )
        case 0x2c:
            target = lambda il: il.sign_extend(2, zT2(il))
            info = InstructionInfo(length=1)
            info.add_branch(BranchType.UnconditionalBranch, target)
            return (
                [tI('jmp2')],
                info,
                lambda il: jump_fixup(il, target(il), adjust=2)
            )
        case 0x0d:
            target = lambda il: il.add(2, il.const_pointer(2, addr), il.sign_extend(2, zT(il)))
            info = InstructionInfo(length=1)
            info.add_branch(BranchType.TrueBranch, target)
            info.add_branch(BranchType.FalseBranch, addr + 1)
            return (
                [tI('jcn')],
                info,
                [
                    lambda il: il_branch(il, il.compare_not_equal(1, zN(il), il.const(1, 0)), target(il), addr + 1, adjust=2)
                ]
            )
        case 0x2d:
            target = lambda il: il.sign_extend(2, zT2(il))
            info = InstructionInfo(length=1)
            info.add_branch(BranchType.UnconditionalBranch, target)
            return (
                [tI('jcn2')],
                info,
                [
                    lambda il: il_branch(il, il.compare_not_equal(1, zL(il), il.const(1, 0)), target(il), addr + 1, adjust=3)
                ]
            )
        case 0x0e:
            target = lambda il: il.add(2, il.const_pointer(2, addr), il.sign_extend(2, zT(il)))
            info = InstructionInfo(length=1)
            return (
                [tI('jsr')],
                info,
                lambda il: jump_fixup(il, target(il), adjust=1, is_call=True)
            )
        case 0x2e:
            target = lambda il: il.sign_extend(2, zT2(il))
            info = InstructionInfo(length=1)
            # info.add_branch(BranchType.CallDestination, target)
            return (
                [tI('jsr2')],
                info,
                lambda il: jump_fixup(il, target(il), adjust=2, is_call=True)
            )
        case 0x10:
            return (
                [tI('ldz')],
                InstructionInfo(length=1),
                lambda il: put(il, 0, il.load(1, il.zero_extend(2, zT(il)))),
                
            )
        case 0x30:
            return (
                [tI('ldz2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(il, 0, il.load(2, il.zero_extend(2, zT(il)))),
                    subi(-1)
                ]
            )
        case 0x11:
            return (
                [tI('stz')],
                InstructionInfo(length=1),
                [
                    lambda il: il.store(1, il.zero_extend(2, zT(il)), zN(il)),
                    subi(2)
                ]
            )
        case 0x31:
            return (
                [tI('stz2')],
                InstructionInfo(length=1),
                [
                    lambda il: il.store(2, il.zero_extend(2, zT(il)), zH2(il)),
                    subi(3)
                ]
            )
        case 0x12:
            return (
                [tI('ldr')],
                InstructionInfo(length=1),
                [
                    lambda il: put(il, 0, il.load(1, il.add(2, il.const(2, addr+1), il.sign_extend(2, zT(il))))),
                ]
            )
        case 0x32:
            return (
                [tI('ldr2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(il, 0, il.load(2, il.add(2, il.const(2, addr+1), il.sign_extend(2, zT(il))))),
                    subi(-1)
                ]
            )
        case 0x13:
            return (
                [tI('str')],
                InstructionInfo(length=1),
                [
                    lambda il: il.store(1, il.add(2, il.const(2, addr + 1), il.sign_extend(2, zT(il))), zN(il)),
                    subi(2)
                ]
            )
        case 0x33:
            return (
                [tI('str2')],
                InstructionInfo(length=1),
                [
                    lambda il: il.store(2, il.add(2, il.const(2, addr + 1), il.sign_extend(2, zT(il))), zH2(il)),
                    subi(3)
                ]
            )
        case 0x14:
            # [c|c]
            # [v]
            if k:
                return (
                    [tI('ldak')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(1, il.load(1, zT2(il))),
                    ]
                )
            else:
                return (
                    [tI('lda')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put(il, 1, il.load(1, zT2(il))),
                        subi(1)
                    ]
                )
        case 0x34:
            # [c|c]
            # [v|v]
            return (
                [tI('lda2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(il, 0, il.load(2, zT2(il))),
                ]
            )
        case 0x15:
            # [n][c|c]
            # 
            return (
                [tI('sta')],
                InstructionInfo(length=1),
                [
                    lambda il: il.store(1, il.zero_extend(2, zT2(il)), zL(il)),
                    subi(3)
                ]
            )
        case 0x35:
            # [n|n][c|c]
            #
            return (
                [tI('sta2')],
                InstructionInfo(length=1),
                [
                    lambda il: il.store(2, il.zero_extend(2, zT2(il)), zN2(il)),
                    subi(4)
                ]
            )
        case 0x16:
            return (
                [tI(f'dei')],
                InstructionInfo(length=1),
                [
                    lambda il: put(il, 0, il.load(1, il.zero_extend(2, zT(il)))),
                ]
            )
        case 0x36:
            return (
                [tI(f'dei2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(il, 0, il.load(2, il.zero_extend(2, zT(il)))),
                    subi(-1)
                ]
            )
        case 0x17:
            if k:
                return (
                    [tI(f'deok')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.store(1, il.zero_extend(2, zT(il)), zN(il)),
                    ]
                )
            else:
                return (
                    [tI(f'deo')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.store(1, il.zero_extend(2, zT(il)), zN(il)),
                        subi(2)
                    ]
                )
        case 0x37:
            if k:
                return (
                    [tI(f'deo2k')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.store(2, il.zero_extend(2, zT(il)), zH2(il)),
                    ]
                )
            else:
                return (
                    [tI(f'deo2')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.store(2, il.zero_extend(2, zT(il)), zH2(il)),
                        subi(3)
                    ]
                )

        case 0x18:
            if k:
                return (
                    [tI(f'addk')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(1, il.add(1, zT(il), zN(il))),
                    ]
                )
            else:
                return (
                    [tI(f'add')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put(il, 1, il.add(1, zT(il), zN(il))),
                        subi(1)
                    ]
                )
        case 0x38:
            if k:
                return (
                    [tI(f'add2k')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(2, il.add(2, zT2(il), zN2(il))),
                    ]
                )
            else:
                return (
                    [tI(f'add2')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put2(il, 2, il.add(2, zT2(il), zN2(il))),
                        subi(2)
                    ]
                )
        case 0x19:
            if k:
                return (
                    [tI(f'subk')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(1, il.sub(1, zN(il), zT(il))),
                    ]
                )
            else:
                return (
                    [tI(f'sub')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put(il, 1, il.sub(1, zN(il), zT(il))),
                        subi(1)
                    ]
                )
        case 0x39:
            if k:
                return (
                    [tI(f'sub2k')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(2, il.sub(2, zN2(il), zT2(il))),
                    ]
                )
            else:
                return (
                    [tI(f'sub2')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put2(il, 2, il.sub(2, zN2(il), zT2(il))),
                        subi(2)
                    ]
                )
        case 0x1a:
            if k:
                return (
                    [tI(f'mul2k')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(1, il.mult(1, zT(il), zN(il))),
                    ]
                )
            else:
                return (
                    [tI(f'mul')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put(il, 1, il.mult(1, zT(il), zN(il))),
                        subi(1)
                    ]
                )
        case 0x3a:
            if k:
                return (
                    [tI(f'mul2k')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(2, il.mult(2, zT2(il), zN2(il))),
                    ]
                )
            else:
                return (
                    [tI(f'mul2')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put2(il, 2, il.mult(2, zT2(il), zN2(il))),
                        subi(2)
                    ]
                )
        case 0x1b:
            if k:
                return (
                    [tI(f'divk')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(1, il.div_signed(1, zN(il), zT(il))),
                    ]
                )
            else:
                return (
                    [tI(f'div')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put(il, 1, il.div_signed(1, zN(il), zT(il))),
                        subi(1)
                    ]
                )
        case 0x3b:
            if k:
                return (
                    [tI(f'div2k')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(2, il.div_signed(2, zN2(il), zT2(il))),
                    ]
                )
            else:
                return (
                    [tI(f'div2')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put2(il, 2, il.div_signed(2, zN2(il), zT2(il))),
                        subi(2)
                    ]
            )
        case 0x1c:
            if k:
                return (
                    [tI(f'andk')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(1, il.and_expr(1, zT(il), zN(il))),
                    ]
                )
            else:
                return (
                    [tI(f'and')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put(il, 1, il.and_expr(1, zT(il), zN(il))),
                        subi(1)
                    ]
                )
        case 0x3c:
            if k:
                return (
                    [tI(f'and2k')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(2, il.and_expr(2, zT2(il), zN2(il))),
                    ]
                )
            else:
                return (
                    [tI(f'and2')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put2(il, 2, il.and_expr(2, zT2(il), zN2(il))),
                        subi(2)
                    ]
                )
        case 0x1d:
            if k:
                return (
                    [tI(f'ork')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(1, il.or_expr(1, zT(il), zN(il))),
                    ]
                )
            else:
                return (
                    [tI(f'or')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put(il, 1, il.or_expr(1, zT(il), zN(il))),
                        subi(1)
                    ]
                )
        case 0x3d:
            if k:
                return (
                    [tI(f'or2k')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(2, il.or_expr(2, zT2(il), zN2(il))),
                    ]
                )
            else:
                return (
                    [tI(f'or2')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put2(il, 2, il.or_expr(2, zT2(il), zN2(il))),
                        subi(2)
                    ]
                )
        case 0x1e:
            if k:
                return (
                    [tI(f'xork')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(1, il.xor_expr(1, zT(il), zN(il))),
                    ]
                )
            else:
                return (
                    [tI(f'xor')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put(il, 1, il.xor_expr(1, zT(il), zN(il))),
                        subi(1)
                    ]
                )
        case 0x3e:
            if k:
                return (
                    [tI(f'xor2k')],
                    InstructionInfo(length=1),
                    [
                        lambda il: il.push(2, il.xor_expr(2, zT2(il), zN2(il))),
                    ]
                )
            else:
                return (
                    [tI(f'xor2')],
                    InstructionInfo(length=1),
                    [
                        lambda il: put2(il, 2, il.xor_expr(2, zT2(il), zN2(il))),
                        subi(2)
                    ]
                )
        case 0x1f:
            # put(0) = (n >> (t & 0xf) << (t >> 4))
            return (
                [tI(f'sft')],
                InstructionInfo(length=1),
                [
                    lambda il: put(
                        il, 1, il.shift_left(
                            1,
                            il.arith_shift_right(1, zN(il), il.and_expr(1, zT(il), il.const(1, 0xf))),
                            il.arith_shift_right(1, zT(il), il.const(1, 4))    
                        ),
                    ),
                    subi(1)
                ]
            )
        case 0x3f:
            # put(0) = (h2 >> (t & 0xf) << (t >> 4))
            return (
                [tI(f'sft2')],
                InstructionInfo(length=1),
                [
                    lambda il: put2(
                        il, 1, il.shift_left(
                            2,
                            il.arith_shift_right(2, zH2(il), il.and_expr(1, zT(il), il.const(1, 0xf))),
                            il.arith_shift_right(1, zT(il), il.const(1, 4))
                        ),
                    ),
                    subi(1)
                ]
            )

    return None
