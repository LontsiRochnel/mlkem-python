from mlkem.encoding import ByteDecode_d, ByteEncode_d


def test_byte_encode_decode_roundtrip():
    values = [(i * 17 + 9) % 3329 for i in range(256)]
    encoded = ByteEncode_d(values, 12)
    decoded = ByteDecode_d(encoded, 12, len(values))
    assert decoded == values
