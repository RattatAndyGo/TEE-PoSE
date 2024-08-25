# TEE-PoSE
A Proof of Secure Erasure implementation as a PTA in OP-TEE.

# How to use
This repository only contains the relevant code for the Secure Erasure PTA. To add it to OP-TEE, copy the file secure-erasure.c to optee-os/core/pta/. Additionally, you need to add a header file with the relevant functions and update sub.mk to make the PTA accessible. 
