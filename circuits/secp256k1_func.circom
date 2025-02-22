pragma circom 2.0.2;

// from https://github.com/ethereum/py_ecc/blob/master/py_ecc/secp256k1/secp256k1.py
function get_gx(n, k) {
    assert(n == 86 && k == 3);
    var ret[100];
    if (n == 86 && k == 3) {
        ret[0] = 17117865558768631194064792;
        ret[1] = 12501176021340589225372855;
        ret[2] = 9198697782662356105779718;
    }
    return ret;
}

function get_gy(n, k) {
    assert(n == 86 && k == 3);
    var ret[100];
    if (n == 86 && k == 3) {
        ret[0] = 6441780312434748884571320;
        ret[1] = 57953919405111227542741658;
        ret[2] = 5457536640262350763842127;
    }
    return ret;
}

function get_secp256k1_prime(n, k) {
     assert(n == 86 && k == 3);
     var ret[100];
     if (n == 86 && k == 3) {
         ret[0] = 77371252455336262886226991;
         ret[1] = 77371252455336267181195263;
         ret[2] = 19342813113834066795298815;
     }
     return ret;
}

function get_secp256k1_order(n, k) {
    assert(n == 86 && k == 3);
    var ret[100];
    if (n == 86 && k == 3) {
        ret[0] = 10428087374290690730508609;
        ret[1] = 77371252455330678278691517;
        ret[2] = 19342813113834066795298815;
    }
    return ret;
}

// (p+1)/4= 28948022309329048855892746252171976963317496166410141009864396001977208667916
// or 3FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF BFFFFF0C
// ret[0]=                                           3FFFFF FFFFFFFF BFFFFF0C (77371252455336266107453196)
// ret[1]=                   3FF FFFFFFFF FFFFFFFF FFF                             
// ret[2]=3FFFFFFF FFFFFFFF FFFFF
function get_secp256k1_primePlus1Devide4(n,k) {
    assert(n == 86 && k == 3);
    var ret[100];
    if (n == 86 && k == 3) {
        ret[0] = 77371252455336266107453196;
        ret[1] = 77371252455336267181195263;
        ret[2] = 4835703278458516698824703;
    }
    return ret;
}

function get_secp256k1_PrimeMinus7(n,k) {
    assert(n == 86 && k == 3);
    var ret[100];
    if (n == 86 && k == 3) {
        ret[0] = 77371252455336266107453189;
        ret[1] = 77371252455336267181195263;
        ret[2] = 4835703278458516698824703;
    }
    return ret;
}
