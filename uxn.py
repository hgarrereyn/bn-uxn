from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo

from .instr import decode, REGS


class UXN(Architecture):
    name = 'uxn:uxn'
    address_size = 2
    max_instr_length = 8

    regs = { r:RegisterInfo(r, 8) for r in REGS }
    stack_pointer = 'sp'

    def __init__(self):
        Architecture.__init__(self)

    def get_instruction_info(self, data, addr):
        r = decode(data, addr)

        if r is None:
            h = InstructionInfo()
            h.length = 2
            return h

        return r[1]

    def get_instruction_text(self, data, addr):
        r = decode(data, addr)

        if r is None:
            return None

        return r[0], r[1].length

    def get_instruction_low_level_il(self, data, addr, il):
        r = decode(data, addr)

        if r is None:
            return 2

        if len(r) >= 3:
            fn = r[2]

            if fn is not None:
                if type(fn) is list:
                    for f in fn:
                        h = f(il)
                        if h is not None:
                            il.append(h)
                else:
                    il.append(fn(il))

            return r[1].length

        return 2
