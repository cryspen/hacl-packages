(module
  (type $0 (func (param i64) (result i64)))
  (type $1 (func (param i32) (result i32)))
  (type $2 (func (param i32) (result i32)))
  (type $3 (func (param i32 i32 i32) (result i32)))
  (type $4 (func (param i32) (result i32)))
  (type $5 (func (param i32) (result i32)))
  (type $6 (func (param i64) (result i32 i32)))
  (type $7 (func (param i32) (result i32)))
  (type $8 (func (param i32) (result i32)))
  (type $9 (func (param i32 i32 i32 i32 i32) (result i32)))
  (type $10 (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type $11 (func (param i32 i32 i32 i32 i32) (result i32)))
  (import "Karamel" "mem" (memory $0 16))
  (import "WasmSupport" "WasmSupport_betole64" (func $0 (type 0)))
  (import "WasmSupport" "WasmSupport_betole32" (func $1 (type 1)))
  (import "WasmSupport" "WasmSupport_betole16" (func $2 (type 2)))
  (import "WasmSupport" "WasmSupport_memzero" (func $3 (type 3)))
  (import "WasmSupport" "WasmSupport_align_64" (func $4 (type 4)))
  (import "WasmSupport" "WasmSupport_malloc" (func $5 (type 5)))
  (import "WasmSupport" "WasmSupport_betole64_packed" (func $6 (type 6)))
  (import "WasmSupport" "WasmSupport_trap" (func $7 (type 7)))
  (import "WasmSupport" "WasmSupport_check_buffer_size" (func $8 (type 8)))
  (import
    "Hacl_HMAC_Blake2s_128"
    "Hacl_HMAC_Blake2s_128_compute_blake2s_128"
    (func $9 (type 9))
  )
  (import "Karamel" "data_start" (global $0 i32))
  (global $1 i32 (i32.const 0))
  (func $10
    (type 10)
    (local
      i64
      i64
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
      i32
    )
    (i32.const 0)
    (i32.load align=1)
    (local.set 10)
    (i32.const 32)
    (local.set 11)
    (local.get 5)
    (local.get 11)
    (i32.div_u)
    (local.set 12)
    (local.get 0)
    (local.set 13)
    (local.get 11)
    (local.get 4)
    (i32.add)
    (i32.const 1)
    (i32.add)
    (local.set 14)
    (local.get 14)
    (call 8)
    (drop)
    (i32.const 0)
    (i32.load align=1)
    (local.get 11)
    (local.get 4)
    (i32.add)
    (i32.const 1)
    (i32.add)
    (i32.const 1)
    (i32.mul)
    (i32.const 1)
    (i32.mul)
    (i32.const 0)
    (i32.load align=1)
    (i32.add)
    (call 4)
    (i32.const 0)
    (local.set 8)
    (local.set 9)
    (local.get 8)
    (local.get 9)
    (i32.store align=1)
    (local.set 15)
    (local.get 15)
    (i32.const 0)
    (i32.store8)
    (local.get 14)
    (i32.const 1)
    (i32.sub)
    (local.set 14)
    (loop
      (local.get 14)
      (i32.const 0)
      (i32.gt_u)
      (if
        (then
          (i32.const 0)
          (i32.load align=1)
          (local.get 15)
          (local.get 14)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (local.get 15)
          (i32.load8_u)
          (i32.store8)
          (local.get 14)
          (i32.const 1)
          (i32.sub)
          (local.set 14)
          (i32.const 0)
          (local.set 8)
          (local.set 9)
          (local.get 8)
          (local.get 9)
          (i32.store align=1)
          (br 1)
        )
        (else (nop))
      )
    )
    (local.get 15)
    (local.set 16)
    (local.get 16)
    (local.get 11)
    (i32.const 1)
    (i32.mul)
    (i32.const 1)
    (i32.mul)
    (i32.add)
    (local.set 17)
    (local.get 16)
    (local.set 18)
    (local.get 16)
    (local.get 11)
    (local.get 4)
    (i32.add)
    (i32.const 1)
    (i32.mul)
    (i32.const 1)
    (i32.mul)
    (i32.add)
    (local.set 19)
    (local.get 3)
    (local.set 20)
    (local.get 16)
    (local.get 11)
    (i32.const 1)
    (i32.mul)
    (i32.const 1)
    (i32.mul)
    (i32.add)
    (local.set 21)
    (local.get 4)
    (local.set 22)
    (loop
      (local.get 22)
      (i32.const 0)
      (i32.gt_u)
      (if
        (then
          (i32.const 0)
          (i32.load align=1)
          (local.get 21)
          (local.get 22)
          (i32.const 1)
          (i32.sub)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (local.get 20)
          (local.get 22)
          (i32.const 1)
          (i32.sub)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (i32.load8_u)
          (i32.store8)
          (local.get 22)
          (i32.const 1)
          (i32.sub)
          (local.set 22)
          (i32.const 0)
          (local.set 8)
          (local.set 9)
          (local.get 8)
          (local.get 9)
          (i32.store align=1)
          (br 1)
        )
        (else (nop))
      )
    )
    (i32.const 0)
    (local.set 23)
    (loop
      (local.get 23)
      (local.get 12)
      (i32.lt_u)
      (if
        (then
          (i32.const 0)
          (i32.load align=1)
          (local.get 19)
          (local.get 23)
          (i32.const 1)
          (i32.add)
          (i32.const 255)
          (i32.and)
          (i32.store8)
          (local.get 23)
          (i32.const 0)
          (i32.eq)
          (if
            (result i32)
            (then
              (local.get 18)
              (local.get 1)
              (local.get 2)
              (local.get 17)
              (local.get 4)
              (i32.const 1)
              (i32.add)
              (call 9)
            )
            (else
              (local.get 18)
              (local.get 1)
              (local.get 2)
              (local.get 16)
              (local.get 11)
              (local.get 4)
              (i32.add)
              (i32.const 1)
              (i32.add)
              (call 9)
            )
          )
          (drop)
          (local.get 18)
          (local.set 24)
          (local.get 13)
          (local.get 23)
          (local.get 11)
          (i32.mul)
          (i32.const 1)
          (i32.mul)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (local.set 25)
          (local.get 11)
          (local.set 26)
          (loop
            (local.get 26)
            (i32.const 0)
            (i32.gt_u)
            (if
              (then
                (i32.const 0)
                (i32.load align=1)
                (local.get 25)
                (local.get 26)
                (i32.const 1)
                (i32.sub)
                (i32.const 1)
                (i32.mul)
                (i32.add)
                (local.get 24)
                (local.get 26)
                (i32.const 1)
                (i32.sub)
                (i32.const 1)
                (i32.mul)
                (i32.add)
                (i32.load8_u)
                (i32.store8)
                (local.get 26)
                (i32.const 1)
                (i32.sub)
                (local.set 26)
                (i32.const 0)
                (local.set 8)
                (local.set 9)
                (local.get 8)
                (local.get 9)
                (i32.store align=1)
                (br 1)
              )
              (else (nop))
            )
          )
          (local.get 23)
          (i32.const 1)
          (i32.add)
          (local.set 23)
          (i32.const 0)
          (local.set 8)
          (local.set 9)
          (local.get 8)
          (local.get 9)
          (i32.store align=1)
          (br 1)
        )
        (else (nop))
      )
    )
    (local.get 12)
    (local.get 11)
    (i32.mul)
    (local.get 5)
    (i32.lt_u)
    (if
      (result i32)
      (then
        (local.get 19)
        (local.get 12)
        (i32.const 1)
        (i32.add)
        (i32.const 255)
        (i32.and)
        (i32.store8)
        (local.get 12)
        (i32.const 0)
        (i32.eq)
        (if
          (result i32)
          (then
            (local.get 18)
            (local.get 1)
            (local.get 2)
            (local.get 17)
            (local.get 4)
            (i32.const 1)
            (i32.add)
            (call 9)
          )
          (else
            (local.get 18)
            (local.get 1)
            (local.get 2)
            (local.get 16)
            (local.get 11)
            (local.get 4)
            (i32.add)
            (i32.const 1)
            (i32.add)
            (call 9)
          )
        )
        (drop)
        (local.get 0)
        (local.get 12)
        (local.get 11)
        (i32.mul)
        (i32.const 1)
        (i32.mul)
        (i32.const 1)
        (i32.mul)
        (i32.add)
        (local.set 27)
        (local.get 18)
        (local.set 28)
        (local.get 27)
        (local.set 29)
        (local.get 5)
        (local.get 12)
        (local.get 11)
        (i32.mul)
        (i32.sub)
        (local.set 30)
        (loop
          (local.get 30)
          (i32.const 0)
          (i32.gt_u)
          (if
            (then
              (i32.const 0)
              (i32.load align=1)
              (local.get 29)
              (local.get 30)
              (i32.const 1)
              (i32.sub)
              (i32.const 1)
              (i32.mul)
              (i32.add)
              (local.get 28)
              (local.get 30)
              (i32.const 1)
              (i32.sub)
              (i32.const 1)
              (i32.mul)
              (i32.add)
              (i32.load8_u)
              (i32.store8)
              (local.get 30)
              (i32.const 1)
              (i32.sub)
              (local.set 30)
              (i32.const 0)
              (local.set 8)
              (local.set 9)
              (local.get 8)
              (local.get 9)
              (i32.store align=1)
              (br 1)
            )
            (else (nop))
          )
        )
        (i32.const 0)
      )
      (else (i32.const -559_038_737))
    )
    (drop)
    (i32.const 0)
    (local.get 10)
    (i32.const 0)
    (local.set 8)
    (local.set 9)
    (local.get 8)
    (local.get 9)
    (i32.store align=1)
  )
  (func $11
    (type 11)
    (local i64 i64 i32 i32 i32)
    (i32.const 0)
    (i32.load align=1)
    (local.set 9)
    (local.get 0)
    (local.get 1)
    (local.get 2)
    (local.get 3)
    (local.get 4)
    (call 9)
    (local.get 9)
    (i32.const 0)
    (local.set 7)
    (local.set 8)
    (local.get 7)
    (local.get 8)
    (i32.store align=1)
  )
  (export "Hacl_HKDF_Blake2s_128_expand_blake2s_128" (func 10))
  (export "Hacl_HKDF_Blake2s_128_extract_blake2s_128" (func 11))
  (export "data_size" (global 1))
  (data $0 (global.get 0))
)
