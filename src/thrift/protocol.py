"""
Thrift TCompact and TBinary protocol implementation.

LINE uses Thrift for all API communication. TCompact (/S4) is the default.
TBinary (/S3) is used for some auth endpoints.
"""

from struct import pack, unpack
from io import BytesIO
from . import types


# ═══════════════════════════════════════════════════════════════
# TCompact Protocol
# ═══════════════════════════════════════════════════════════════

class TCompactProtocol:
    """
    Apache Thrift TCompact protocol.
    
    Compact uses variable-length encoding (zigzag + varint) and delta
    field IDs for smaller payloads. LINE uses this on /S4.
    """

    # Compact type mapping
    COMPACT_TYPES = {
        types.STOP: 0,
        types.BOOL_TRUE: 1,
        types.BOOL_FALSE: 2,
        types.BYTE: 3,
        types.I16: 4,
        types.I32: 5,
        types.I64: 6,
        types.DOUBLE: 7,
        types.BINARY: 8,
        types.LIST: 9,
        types.SET: 10,
        types.MAP: 11,
        types.STRUCT: 12,
    }

    COMPACT_TO_THRIFT = {v: k for k, v in COMPACT_TYPES.items()}

    PROTOCOL_ID = 0x82
    VERSION = 1
    VERSION_MASK = 0x1F
    TYPE_MASK = 0xE0
    TYPE_SHIFT = 5

    # ── Writer ──

    class Writer:
        def __init__(self):
            self.buf = BytesIO()
            self._field_stack = []  # stack of last_field_id for nested structs
            self._last_field_id = 0

        def _write_byte(self, val: int):
            self.buf.write(pack('b', val))

        def _write_ubyte(self, val: int):
            self.buf.write(pack('B', val))

        def _write_varint(self, val: int):
            """Write unsigned varint."""
            while True:
                if val & ~0x7F == 0:
                    self._write_ubyte(val)
                    break
                self._write_ubyte((val & 0x7F) | 0x80)
                val >>= 7

        def _write_zigzag(self, val: int):
            """Write signed zigzag-encoded varint."""
            self._write_varint((val << 1) ^ (val >> 63))

        def write_message_begin(self, name: str, msg_type: int, seqid: int):
            self._write_ubyte(self.PROTOCOL_ID)
            self._write_ubyte((self.VERSION & self.VERSION_MASK) | 
                            ((msg_type << self.TYPE_SHIFT) & self.TYPE_MASK))
            self._write_varint(seqid)
            self._write_binary(name.encode('utf-8'))

        def write_message_end(self):
            pass

        def write_struct_begin(self):
            self._field_stack.append(self._last_field_id)
            self._last_field_id = 0

        def write_struct_end(self):
            self._last_field_id = self._field_stack.pop()

        def write_field_begin(self, field_type: int, field_id: int):
            compact_type = TCompactProtocol.COMPACT_TYPES.get(field_type, field_type)
            delta = field_id - self._last_field_id
            if 0 < delta <= 15:
                self._write_ubyte((delta << 4) | compact_type)
            else:
                self._write_ubyte(compact_type)
                self._write_zigzag(field_id)  # use zigzag for field ID
            self._last_field_id = field_id

        def write_field_stop(self):
            self._write_ubyte(0)

        def write_bool(self, val: bool):
            # Bool is encoded in the field header type nibble
            # But for standalone: 1=true, 0=false
            self._write_ubyte(1 if val else 0)

        def write_bool_field(self, field_id: int, val: bool):
            """Write a bool as part of a field (type embedded in header)."""
            compact_type = types.BOOL_TRUE if val else types.BOOL_FALSE
            delta = field_id - self._last_field_id
            if 0 < delta <= 15:
                self._write_ubyte((delta << 4) | compact_type)
            else:
                self._write_ubyte(compact_type)
                self._write_zigzag(field_id)
            self._last_field_id = field_id

        def write_byte(self, val: int):
            self._write_byte(val)

        def write_i16(self, val: int):
            self._write_zigzag(val)

        def write_i32(self, val: int):
            self._write_zigzag(val)

        def write_i64(self, val: int):
            self._write_zigzag(val)

        def write_double(self, val: float):
            self.buf.write(pack('<d', val))  # little-endian for compact

        def _write_binary(self, val: bytes):
            self._write_varint(len(val))
            self.buf.write(val)

        def write_string(self, val: str):
            self._write_binary(val.encode('utf-8'))

        def write_binary(self, val: bytes):
            self._write_binary(val)

        def write_map_begin(self, key_type: int, val_type: int, size: int):
            if size == 0:
                self._write_ubyte(0)
            else:
                self._write_varint(size)
                kt = TCompactProtocol.COMPACT_TYPES.get(key_type, key_type)
                vt = TCompactProtocol.COMPACT_TYPES.get(val_type, val_type)
                self._write_ubyte((kt << 4) | vt)

        def write_list_begin(self, elem_type: int, size: int):
            ct = TCompactProtocol.COMPACT_TYPES.get(elem_type, elem_type)
            if size <= 14:
                self._write_ubyte((size << 4) | ct)
            else:
                self._write_ubyte(0xF0 | ct)
                self._write_varint(size)

        def write_set_begin(self, elem_type: int, size: int):
            self.write_list_begin(elem_type, size)

        def getvalue(self) -> bytes:
            return self.buf.getvalue()

        # Aliases
        PROTOCOL_ID = 0x82
        VERSION = 1
        VERSION_MASK = 0x1F
        TYPE_MASK = 0xE0
        TYPE_SHIFT = 5

    # ── Reader ──

    class Reader:
        def __init__(self, data: bytes):
            self.buf = BytesIO(data)
            self._field_stack = []
            self._last_field_id = 0
            self._bool_value = None

        def _read_ubyte(self) -> int:
            b = self.buf.read(1)
            if not b:
                raise EOFError("End of data")
            return b[0]

        def _read_byte(self) -> int:
            val, = unpack('b', self.buf.read(1))
            return val

        def _read_varint(self) -> int:
            result = 0
            shift = 0
            while True:
                b = self._read_ubyte()
                result |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            return result

        def _read_zigzag(self) -> int:
            val = self._read_varint()
            return (val >> 1) ^ -(val & 1)

        def read_message_begin(self) -> tuple:
            proto_id = self._read_ubyte()
            if proto_id != TCompactProtocol.PROTOCOL_ID:
                raise ValueError(f"Bad protocol id: {proto_id:#x}")
            ver_type = self._read_ubyte()
            version = ver_type & TCompactProtocol.VERSION_MASK
            if version != TCompactProtocol.VERSION:
                raise ValueError(f"Bad version: {version}")
            msg_type = (ver_type >> TCompactProtocol.TYPE_SHIFT) & 0x07
            seqid = self._read_varint()
            name_len = self._read_varint()
            name = self.buf.read(name_len).decode('utf-8')
            return name, msg_type, seqid

        def read_field_begin(self) -> tuple:
            """Returns (field_type, field_id). field_type=STOP means end."""
            byte = self._read_ubyte()
            if byte == 0:
                return types.STOP, 0

            compact_type = byte & 0x0F
            delta = (byte >> 4) & 0x0F

            if delta != 0:
                field_id = self._last_field_id + delta
            else:
                field_id = self._read_zigzag()

            # Handle bools (type embedded in field header)
            if compact_type == 1:  # BOOL_TRUE
                self._bool_value = True
                field_type = types.BOOL_TRUE
            elif compact_type == 2:  # BOOL_FALSE
                self._bool_value = False
                field_type = types.BOOL_FALSE
            else:
                field_type = TCompactProtocol.COMPACT_TO_THRIFT.get(compact_type, compact_type)

            self._last_field_id = field_id
            return field_type, field_id

        def read_struct_begin(self):
            self._field_stack.append(self._last_field_id)
            self._last_field_id = 0

        def read_struct_end(self):
            self._last_field_id = self._field_stack.pop()

        def read_bool(self) -> bool:
            if self._bool_value is not None:
                val = self._bool_value
                self._bool_value = None
                return val
            return self._read_ubyte() == 1

        def read_byte(self) -> int:
            return self._read_byte()

        def read_i16(self) -> int:
            return self._read_zigzag()

        def read_i32(self) -> int:
            return self._read_zigzag()

        def read_i64(self) -> int:
            return self._read_zigzag()

        def read_double(self) -> float:
            val, = unpack('<d', self.buf.read(8))
            return val

        def read_string(self) -> str:
            length = self._read_varint()
            data = self.buf.read(length)
            return data.decode('utf-8')

        def read_binary(self) -> bytes:
            length = self._read_varint()
            return self.buf.read(length)

        def read_map_begin(self) -> tuple:
            size = self._read_varint()
            if size == 0:
                return types.BYTE, types.BYTE, 0
            type_byte = self._read_ubyte()
            key_type = TCompactProtocol.COMPACT_TO_THRIFT.get((type_byte >> 4) & 0x0F, (type_byte >> 4) & 0x0F)
            val_type = TCompactProtocol.COMPACT_TO_THRIFT.get(type_byte & 0x0F, type_byte & 0x0F)
            return key_type, val_type, size

        def read_list_begin(self) -> tuple:
            size_type = self._read_ubyte()
            size = (size_type >> 4) & 0x0F
            elem_type = TCompactProtocol.COMPACT_TO_THRIFT.get(size_type & 0x0F, size_type & 0x0F)
            if size == 15:
                size = self._read_varint()
            return elem_type, size

        def read_set_begin(self) -> tuple:
            return self.read_list_begin()

        def skip(self, field_type: int):
            """Skip over a value of given type."""
            if field_type in (types.BOOL_TRUE, types.BOOL_FALSE):
                self.read_bool()
            elif field_type == types.BYTE:
                self.read_byte()
            elif field_type == types.I16:
                self.read_i16()
            elif field_type == types.I32:
                self.read_i32()
            elif field_type == types.I64:
                self.read_i64()
            elif field_type == types.DOUBLE:
                self.read_double()
            elif field_type == types.BINARY:
                self.read_binary()
            elif field_type == types.STRUCT:
                self.read_struct_begin()
                while True:
                    ft, _ = self.read_field_begin()
                    if ft == types.STOP:
                        break
                    self.skip(ft)
                self.read_struct_end()
            elif field_type == types.MAP:
                kt, vt, size = self.read_map_begin()
                for _ in range(size):
                    self.skip(kt)
                    self.skip(vt)
            elif field_type in (types.LIST, types.SET):
                et, size = self.read_list_begin()
                for _ in range(size):
                    self.skip(et)

    @staticmethod
    def write_request(method: str, params: list, seqid: int = 0) -> bytes:
        """
        Encode a Thrift TCompact method call.
        
        params: list of (field_type, field_id, value) tuples.
        """
        w = TCompactProtocol.Writer()
        w.write_message_begin(method, types.CALL, seqid)
        _write_struct_fields(w, params)
        w.write_field_stop()
        return w.getvalue()

    @staticmethod
    def read_response(data: bytes) -> dict:
        """
        Decode a Thrift TCompact response into a dict of {field_id: value}.
        """
        r = TCompactProtocol.Reader(data)
        name, msg_type, seqid = r.read_message_begin()

        if msg_type == types.EXCEPTION:
            # Application exception
            result = _read_struct(r)
            raise ThriftException(result.get(1, ""), result.get(2, 0))

        return _read_struct(r)


# ═══════════════════════════════════════════════════════════════
# TBinary Protocol (used for some auth endpoints)
# ═══════════════════════════════════════════════════════════════

class TBinaryProtocol:
    """
    Apache Thrift TBinary protocol. Used on /S3 and some auth endpoints.
    """

    VERSION_1 = -2147418112  # 0x80010000 as signed int32
    VERSION_MASK = 0xFFFF0000

    @staticmethod
    def write_request(method: str, params: list, seqid: int = 0) -> bytes:
        buf = BytesIO()
        # Message header
        version = TBinaryProtocol.VERSION_1 | types.CALL
        buf.write(pack('!i', version))
        method_bytes = method.encode('utf-8')
        buf.write(pack('!i', len(method_bytes)))
        buf.write(method_bytes)
        buf.write(pack('!i', seqid))
        # Fields
        _write_binary_struct_fields(buf, params)
        buf.write(pack('b', 0))  # STOP
        return buf.getvalue()

    @staticmethod
    def read_response(data: bytes) -> dict:
        buf = BytesIO(data)
        sz, = unpack('!i', buf.read(4))
        if sz < 0:
            version = sz & TBinaryProtocol.VERSION_MASK
            if version != TBinaryProtocol.VERSION_1:
                raise ValueError(f"Bad version: {version:#x}")
            msg_type = sz & 0xFF
            name_len, = unpack('!i', buf.read(4))
            buf.read(name_len)  # method name
            buf.read(4)  # seqid
        if msg_type == types.EXCEPTION:
            result = _read_binary_struct(buf)
            raise ThriftException(result.get(1, ""), result.get(2, 0))
        return _read_binary_struct(buf)


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

class ThriftException(Exception):
    def __init__(self, message: str = "", code: int = 0):
        self.message = message
        self.code = code
        super().__init__(f"ThriftException(code={code}): {message}")


def _write_struct_fields(w: TCompactProtocol.Writer, params: list):
    """
    Write CHRLINE-style param list:
    Each param is [thrift_type, field_id, value]
    For structs: [12, field_id, [nested fields...]]
    For maps: [13, field_id, [key_type, val_type, {k: v, ...}]]
    For lists: [15, field_id, [elem_type, [items...]]]
    """
    for param in params:
        ftype, fid, value = param[0], param[1], param[2]

        if ftype == 2:  # bool
            w.write_bool_field(fid, value)
        elif ftype == 3:  # byte
            w.write_field_begin(types.BYTE, fid)
            w.write_byte(value)
        elif ftype == 4:  # double
            w.write_field_begin(types.DOUBLE, fid)
            w.write_double(value)
        elif ftype == 6:  # i16
            w.write_field_begin(types.I16, fid)
            w.write_i16(value)
        elif ftype == 8:  # i32
            w.write_field_begin(types.I32, fid)
            w.write_i32(value)
        elif ftype == 10:  # i64
            w.write_field_begin(types.I64, fid)
            w.write_i64(value)
        elif ftype == 11:  # string
            w.write_field_begin(types.BINARY, fid)
            if value is None:
                w.write_string("")
            else:
                w.write_string(str(value))
        elif ftype == 12:  # struct
            w.write_field_begin(types.STRUCT, fid)
            w.write_struct_begin()
            if isinstance(value, list):
                _write_struct_fields(w, value)
            w.write_field_stop()
            w.write_struct_end()
        elif ftype == 13:  # map
            key_type, val_type, map_data = value[0], value[1], value[2]
            w.write_field_begin(types.MAP, fid)
            _kt = _legacy_type_to_compact(key_type)
            _vt = _legacy_type_to_compact(val_type)
            w.write_map_begin(_kt, _vt, len(map_data))
            for k, v in map_data.items():
                _write_value(w, _kt, k)
                _write_value(w, _vt, v)
        elif ftype == 15:  # list
            elem_type, items = value[0], value[1]
            w.write_field_begin(types.LIST, fid)
            _et = _legacy_type_to_compact(elem_type)
            w.write_list_begin(_et, len(items))
            for item in items:
                _write_value(w, _et, item)


def _write_value(w, thrift_type, value):
    """Write a single value by type."""
    if thrift_type == types.BINARY:
        if isinstance(value, bytes):
            w.write_binary(value)
        else:
            w.write_string(str(value))
    elif thrift_type == types.I32:
        w.write_i32(value)
    elif thrift_type == types.I64:
        w.write_i64(value)
    elif thrift_type == types.I16:
        w.write_i16(value)
    elif thrift_type == types.BYTE:
        w.write_byte(value)
    elif thrift_type == types.DOUBLE:
        w.write_double(value)
    elif thrift_type in (types.BOOL_TRUE, types.BOOL_FALSE):
        w.write_bool(value)
    elif thrift_type == types.STRUCT:
        w.write_struct_begin()
        if isinstance(value, list):
            _write_struct_fields(w, value)
        w.write_field_stop()
        w.write_struct_end()


def _legacy_type_to_compact(legacy_type: int) -> int:
    """Convert CHRLINE-style type IDs (TBinary numbering) to Thrift type constants."""
    mapping = {
        2: types.BOOL_TRUE, 3: types.BYTE, 4: types.DOUBLE,
        6: types.I16, 8: types.I32, 10: types.I64,
        11: types.BINARY, 12: types.STRUCT, 13: types.MAP,
        14: types.SET, 15: types.LIST,
    }
    return mapping.get(legacy_type, legacy_type)


def _read_struct(r: TCompactProtocol.Reader) -> dict:
    """Read a struct into {field_id: value}."""
    result = {}
    r.read_struct_begin()
    while True:
        ftype, fid = r.read_field_begin()
        if ftype == types.STOP:
            break
        result[fid] = _read_value(r, ftype)
    r.read_struct_end()
    return result


def _read_value(r: TCompactProtocol.Reader, ftype: int):
    """Read a single value by type."""
    if ftype in (types.BOOL_TRUE, types.BOOL_FALSE):
        return r.read_bool()
    elif ftype == types.BYTE:
        return r.read_byte()
    elif ftype == types.I16:
        return r.read_i16()
    elif ftype == types.I32:
        return r.read_i32()
    elif ftype == types.I64:
        return r.read_i64()
    elif ftype == types.DOUBLE:
        return r.read_double()
    elif ftype == types.BINARY:
        return r.read_binary()
    elif ftype == types.STRUCT:
        return _read_struct(r)
    elif ftype == types.MAP:
        kt, vt, size = r.read_map_begin()
        return {_read_value(r, kt): _read_value(r, vt) for _ in range(size)}
    elif ftype in (types.LIST, types.SET):
        et, size = r.read_list_begin()
        return [_read_value(r, et) for _ in range(size)]
    else:
        r.skip(ftype)
        return None


# ── TBinary helpers ──

def _write_binary_struct_fields(buf: BytesIO, params: list):
    """Write CHRLINE-style params in TBinary format."""
    for param in params:
        ftype, fid, value = param[0], param[1], param[2]
        buf.write(pack('b', ftype))
        buf.write(pack('!h', fid))
        _write_binary_value(buf, ftype, value)


def _write_binary_value(buf: BytesIO, ftype: int, value):
    if ftype == 2:  # bool
        buf.write(pack('b', 1 if value else 0))
    elif ftype == 3:  # byte
        buf.write(pack('b', value))
    elif ftype == 4:  # double
        buf.write(pack('!d', value))
    elif ftype == 6:  # i16
        buf.write(pack('!h', value))
    elif ftype == 8:  # i32
        buf.write(pack('!i', value))
    elif ftype == 10:  # i64
        buf.write(pack('!q', value))
    elif ftype == 11:  # string
        s = (value or "").encode('utf-8')
        buf.write(pack('!i', len(s)))
        buf.write(s)
    elif ftype == 12:  # struct
        if isinstance(value, list):
            _write_binary_struct_fields(buf, value)
        buf.write(pack('b', 0))  # STOP
    elif ftype == 13:  # map
        key_type, val_type, map_data = value[0], value[1], value[2]
        buf.write(pack('b', key_type))
        buf.write(pack('b', val_type))
        buf.write(pack('!i', len(map_data)))
        for k, v in map_data.items():
            _write_binary_value(buf, key_type, k)
            _write_binary_value(buf, val_type, v)
    elif ftype == 15:  # list
        elem_type, items = value[0], value[1]
        buf.write(pack('b', elem_type))
        buf.write(pack('!i', len(items)))
        for item in items:
            _write_binary_value(buf, elem_type, item)


def _read_binary_struct(buf: BytesIO) -> dict:
    result = {}
    while True:
        ftype, = unpack('b', buf.read(1))
        if ftype == 0:
            break
        fid, = unpack('!h', buf.read(2))
        result[fid] = _read_binary_value(buf, ftype)
    return result


def _read_binary_value(buf: BytesIO, ftype: int):
    if ftype == 2:
        return unpack('b', buf.read(1))[0] != 0
    elif ftype == 3:
        return unpack('b', buf.read(1))[0]
    elif ftype == 4:
        return unpack('!d', buf.read(8))[0]
    elif ftype == 6:
        return unpack('!h', buf.read(2))[0]
    elif ftype == 8:
        return unpack('!i', buf.read(4))[0]
    elif ftype == 10:
        return unpack('!q', buf.read(8))[0]
    elif ftype == 11:
        size = unpack('!i', buf.read(4))[0]
        data = buf.read(size)
        try:
            return data.decode('utf-8')
        except:
            return data
    elif ftype == 12:
        return _read_binary_struct(buf)
    elif ftype == 13:
        kt = unpack('b', buf.read(1))[0]
        vt = unpack('b', buf.read(1))[0]
        size = unpack('!i', buf.read(4))[0]
        return {_read_binary_value(buf, kt): _read_binary_value(buf, vt) for _ in range(size)}
    elif ftype in (14, 15):
        et = unpack('b', buf.read(1))[0]
        size = unpack('!i', buf.read(4))[0]
        return [_read_binary_value(buf, et) for _ in range(size)]
    else:
        return None
