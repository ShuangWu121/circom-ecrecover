# circom-ecrecover

Implementation of ecrecover in circom.

## Project overview

[Circom](https://github.com/iden3/circom/) is a circuit compiler written in Rust for compiling circuits written in the circom language. I found it is easy to use, so I learn it and use it to build the circuit of ecrecover.


[Circom-ecdsa](https://github.com/0xPARC/circom-ecdsa) is a implementation of ECDSA operations in circom, where you can also find the instructions for buiding this repository (pot25_final.ptau is necessary for mine), and I used most of there operations, like big number operations, specp256k1 operations.





## Overview

The main algorithm is in circom-ecrecover/circuit/ecrecover.cricom

I mainly implement the follwing constrains

-Check the validation of x, i.e. r, that is,
    
    
    1. Derive y from x, using the equation of the curve
    2. test if (x,y) is on the curve

-Check s is valid (s is not zero or 1)

-Compute the public key, set the point (r,y) as X, then the public key is: $pubkey=s*r^{-1}*X-e*r^{-1}*G$

The most expensive part is derive y from x (I thought it is needed, maybe not?), which needs to use exp operation of big number. The code shows that the circuit has 9503784 constrains. Then it tells me I don't have enough memeory to run the follwing part, which seems to generate the whole common reference.

run: 

`yarn build:ecrecover` 

I hope later I can have time to fix the problem, it is a very interesting task, but I didn't got enough time to work on it in last two weeks. :(  