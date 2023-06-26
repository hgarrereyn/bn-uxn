from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, SymbolType
from binaryninja.types import Symbol

device_info = {
    0x00: ('system_halt', 2),
    0x02: ('system_expansion', 2),
    0x04: ('system_friend', 2),
    0x06: ('system_metadata', 2),
    0x08: ('system_red', 2),
    0x0a: ('system_green', 2),
    0x0c: ('system_blue', 2),
    0x0e: ('system_debug', 1),
    0x0f: ('system_state', 1),

    0x10: ('console_vector', 2),
    0x12: ('console_read', 1),
    0x17: ('console_type', 1),
    0x18: ('console_write', 1),
    0x19: ('console_error', 1),

    0x20: ('screen_vector', 2),
    0x22: ('screen_width', 2),
    0x24: ('screen_height', 2),
    0x26: ('screen_auto', 1),
    0x28: ('screen_x', 2),
    0x2a: ('screen_y', 2),
    0x2c: ('screen_addr', 2),
    0x2e: ('screen_pixel', 1),
    0x2f: ('screen_sprite', 1),

    0x30: ('audio_vector', 2),
    0x32: ('audio_position', 2),
    0x34: ('audio_output', 1),
    0x38: ('audio_adsr', 2),
    0x3a: ('audio_length', 2),
    0x3c: ('audio_addr', 2),
    0x3e: ('audio_volume', 1),
    0x3f: ('audio_pitch', 1),

    0x80: ('controller_vector', 2),
    0x82: ('controller_button', 1),
    0x83: ('controller_key', 1),
}

class UXNView(BinaryView):
    name = "uxn"
    long_name = "uxn"

    @classmethod
    def is_valid_for_data(self, data: BinaryView):
        return True

    def __init__(self, data: BinaryView):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['uxn:uxn'].standalone_platform
        self.data = data

    def init(self):
        # Device memory
        self.add_auto_segment(0, 0x100, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        # RAM
        self.add_auto_segment(0x100, self.data.length, 0, self.data.length, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)

        for addr, (name, size) in device_info.items():
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))

        self.add_entry_point(0x100)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x100

    def perform_get_address_size(self) -> int:
        return 2
