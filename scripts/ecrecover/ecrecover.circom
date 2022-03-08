pragma circom 2.0.2;

include "../../circuits/ecrecover.circom";

component main {public [r, s, v, msghash]} = Ecrecover(86, 3);
