from mlkem import (
    CT_SIZE,
    DK_SIZE,
    EK_SIZE,
    ML_KEM_1024,
    ML_KEM_512,
    ML_KEM_768,
    SS_SIZE,
)


def test_sizes():
    assert EK_SIZE[ML_KEM_512] == 800
    assert DK_SIZE[ML_KEM_512] == 1632
    assert CT_SIZE[ML_KEM_512] == 768
    assert EK_SIZE[ML_KEM_768] == 1184
    assert DK_SIZE[ML_KEM_768] == 2400
    assert CT_SIZE[ML_KEM_768] == 1088
    assert EK_SIZE[ML_KEM_1024] == 1568
    assert DK_SIZE[ML_KEM_1024] == 3168
    assert CT_SIZE[ML_KEM_1024] == 1568
    assert SS_SIZE == 32
