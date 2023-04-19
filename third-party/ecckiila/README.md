The files in this directory were generated from ecckiila:
https://gitlab.com/nisec/ecckiila
We took code from commit 74f3d38d

We generated code following instructions in:
https://gitlab.com/nisec/ecckiila/-/blob/master/README.md

We cleaned up the generated code using unifdef:
unifdef ../original-code.c -DRIG_NULL -URIG_GOST -URIG_NSS -UOPENSSL_BUILDING_OPENSSL -UKIILA_OPENSSL_EMIT_CURVEDEF -ULIB_TEST > output-code.c




