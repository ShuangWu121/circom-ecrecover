pragma circom 2.0.2;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "bigint.circom";
include "secp256k1.circom";
include "bigint_func.circom";
include "ecdsa_func.circom";
include "secp256k1_func.circom";
include "ecdsa.circom";



/*

-Check the validation of x, i.e. r, that is,
    
    1. x is in the correct range
    1. Derive y from x, using the equation of the curve
    2. test if (x,y) is on the curve

-Check s is valid (s is not zero or 1)

-Compute the public key, set the point (r,y) as X, then the public key is: pubkey=s*r^{-1}*X-e*r^{-1}*G

*/



// r, s, msghash, have coordinates
// encoded with k registers of n bits each
// signature is (r, s)


template Ecrecover(n,k){
    assert(k >= 2);
    assert(k <= 100);

    signal input r[k];
    signal input s[k];
    signal input v;
    signal input msghash[k];

    // signal validation shows if x is valid
    signal output validation;
    signal output pubkey[2][k];

    var p[100] = get_secp256k1_prime(n, k);
    var order[100] = get_secp256k1_order(n, k);

    // to compute the square root of y, I compute y^{(p+1)/4}, pDiv4=(p+1)/4
    var pDiv4[100] =get_secp256k1_primePlus1Devide4(n,k);

    // Compute x^3+7
    //somehow the modular addition for big number always has bugs, 
    //so I compute x^3-(p-7) mod p instead, so I use BigSubMod function, b=p-7
    
    var b[100]=get_secp256k1_PrimeMinus7(n,k);

    // derive y from r
    // compute x^3+7
    component r_double=BigMultModP(n, k);
    for (var idx = 0; idx < k; idx++) {
        r_double.a[idx] <== r[idx];
        r_double.b[idx] <== r[idx];
        r_double.p[idx] <== p[idx];
    }
    component r_triple=BigMultModP(n, k);
    for (var idx = 0; idx < k; idx++) {
        r_triple.a[idx] <== r[idx];
        r_triple.b[idx] <== r_double.out[idx];
        r_triple.p[idx] <== p[idx];
    }

    component r_triple_plus7=BigSubModP(n,k);
    for (var idx = 0; idx < k; idx++) {
        r_triple_plus7.a[idx] <== r_triple.out[idx];
        r_triple_plus7.b[idx] <== b[idx];
        r_triple_plus7.p[idx] <== p[idx];

    }
    

    //compute y=squre roof of (x^3+7), that is SqureRoot(y)=y^{(p+1)/4} mod p
    signal computeY[k];
    for (var idx = 0; idx < k; idx++) {
        computeY[idx] <== r_triple_plus7.out[idx];
    }

    var yLong[100]=mod_exp(n,k,computeY,p,pDiv4);

    component PSubylong=BigSubModP(n,k);
    for (var idx = 0; idx < k; idx++) {
        PSubylong.a[idx] <== p[idx];
        PSubylong.b[idx] <-- yLong[idx];
        PSubylong.p[idx] <== p[idx];

    }

    //choose the correct y based on v

    signal yflag;
    yflag<==yLong[k]<<(n-1);

    signal vflag;
    vflag<--v<<(n-1);



    //flag=ylong % 2
    //y=ylong (flag* (v%2))+y() 


    signal y[k];
    for (var idx = 0; idx < k; idx++) {
        y[idx] <-- yLong[idx]*!(yflag^vflag)+PSubylong.out[idx]*(yflag^vflag);
    }

    component OnCurve=Secp256k1PointOnCurve(n,k);
    for (var idx = 0; idx < k; idx++) {
        OnCurve.x[idx] <== r[idx];
        OnCurve.y[idx] <== y[idx];
    }

    validation<==OnCurve.out;


    //check s range,this range check is from https://github.com/0xPARC/circom-ecdsa

    // compute multiplicative inverse of s mod n
    var sinv_comp[100] = mod_inv(n, k, s, order);
    signal sinv[k];
    component sinv_range_checks[k];
    for (var idx = 0; idx < k; idx++) {
        sinv[idx] <-- sinv_comp[idx];
        sinv_range_checks[idx] = Num2Bits(n);
        sinv_range_checks[idx].in <== sinv[idx];
    }
    component sinv_check = BigMultModP(n, k);
    for (var idx = 0; idx < k; idx++) {
        sinv_check.a[idx] <== sinv[idx];
        sinv_check.b[idx] <== s[idx];
        sinv_check.p[idx] <== order[idx];
    }
    for (var idx = 0; idx < k; idx++) {
        if (idx > 0) {
            sinv_check.out[idx] === 0;
        }
        if (idx == 0) {
            sinv_check.out[idx] === 1;
        }
    }


     // compute multiplicative inverse of r mod n
    var rinv_comp[100] = mod_inv(n, k, r, order);
    signal rinv[k];
    component rinv_range_checks[k];
    for (var idx = 0; idx < k; idx++) {
        rinv[idx] <-- rinv_comp[idx];
        rinv_range_checks[idx] = Num2Bits(n);
        rinv_range_checks[idx].in <== rinv[idx];
    }
    component rinv_check = BigMultModP(n, k);
    for (var idx = 0; idx < k; idx++) {
        rinv_check.a[idx] <== rinv[idx];
        rinv_check.b[idx] <== r[idx];
        rinv_check.p[idx] <== order[idx];
    }
    for (var idx = 0; idx < k; idx++) {
        if (idx > 0) {
            rinv_check.out[idx] === 0;
        }
        if (idx == 0) {
            rinv_check.out[idx] === 1;
        }
    }

    //compute s* rinv, point X is (r,y)

    component X_coeff = BigMultModP(n, k);
    for (var idx = 0; idx < k; idx++) {
        X_coeff.a[idx] <== rinv[idx];
        X_coeff.b[idx] <== s[idx];
        X_coeff.p[idx] <== order[idx];
    }

    // compute (s* rinv) * X
    component sMulrinvMulX = Secp256k1ScalarMult(n, k);
    for (var idx = 0; idx < k; idx++) {
        sMulrinvMulX.scalar[idx] <== X_coeff.out[idx];
        sMulrinvMulX.point[0][idx] <== r[idx];
        sMulrinvMulX.point[1][idx] <== y[idx];
    }

    // compute (msghash * rinv) mod n
    component g_coeff = BigMultModP(n, k);
    for (var idx = 0; idx < k; idx++) {
        g_coeff.a[idx] <== rinv[idx];
        g_coeff.b[idx] <== msghash[idx];
        g_coeff.p[idx] <== order[idx];
    }

    // compute (msghash * rinv) * G
    component hMulrinvMulG = ECDSAPrivToPub(n, k);
    for (var idx = 0; idx < k; idx++) {
        hMulrinvMulG.privkey[idx] <== g_coeff.out[idx];
    }

    // compute (s* rinv) * X + (msghash * rinv) * G
    component FinalPubkey = Secp256k1AddUnequal(n, k);
    for (var idx = 0; idx < k; idx++) {
        FinalPubkey.a[0][idx] <== sMulrinvMulX.out[0][idx];
        FinalPubkey.a[1][idx] <== sMulrinvMulX.out[1][idx];
        FinalPubkey.b[0][idx] <== hMulrinvMulG.pubkey[0][idx];
        FinalPubkey.b[1][idx] <== hMulrinvMulG.pubkey[1][idx];
    }
    


}

