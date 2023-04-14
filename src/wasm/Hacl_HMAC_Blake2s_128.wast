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
  (type $9 (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type $10 (func (param i32 i32 i32 i32 i32) (result i32)))
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
  (import "Hacl_Hash_Blake2s_128" "Hacl_Blake2s_128_blake2s" (func $9 (type 9)))
  (import "Karamel" "data_start" (global $0 i32))
  (global $1 i32 (i32.const 158))
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
      i32
      i32
    )
    (i32.const 0)
    (i32.load align=1)
    (local.set 9)
    (i32.const 64)
    (local.set 10)
    (local.get 10)
    (local.set 11)
    (local.get 11)
    (call 8)
    (drop)
    (i32.const 0)
    (i32.load align=1)
    (local.get 10)
    (i32.const 1)
    (i32.mul)
    (i32.const 1)
    (i32.mul)
    (i32.const 0)
    (i32.load align=1)
    (i32.add)
    (call 4)
    (i32.const 0)
    (local.set 7)
    (local.set 8)
    (local.get 7)
    (local.get 8)
    (i32.store align=1)
    (local.set 12)
    (local.get 12)
    (i32.const 0)
    (i32.store8)
    (local.get 11)
    (i32.const 1)
    (i32.sub)
    (local.set 11)
    (loop
      (local.get 11)
      (i32.const 0)
      (i32.gt_u)
      (if
        (then
          (i32.const 0)
          (i32.load align=1)
          (local.get 12)
          (local.get 11)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (local.get 12)
          (i32.load8_u)
          (i32.store8)
          (local.get 11)
          (i32.const 1)
          (i32.sub)
          (local.set 11)
          (i32.const 0)
          (local.set 7)
          (local.set 8)
          (local.get 7)
          (local.get 8)
          (i32.store align=1)
          (br 1)
        )
        (else (nop))
      )
    )
    (local.get 12)
    (local.set 13)
    (local.get 2)
    (i32.const 64)
    (i32.le_u)
    (if (result i32) (then (local.get 2)) (else (i32.const 32)))
    (local.set 14)
    (local.get 13)
    (local.set 15)
    (local.get 2)
    (i32.const 64)
    (i32.le_u)
    (if
      (result i32)
      (then
        (local.get 1)
        (local.set 16)
        (local.get 15)
        (local.set 17)
        (local.get 2)
        (local.set 18)
        (loop
          (local.get 18)
          (i32.const 0)
          (i32.gt_u)
          (if
            (then
              (i32.const 0)
              (i32.load align=1)
              (local.get 17)
              (local.get 18)
              (i32.const 1)
              (i32.sub)
              (i32.const 1)
              (i32.mul)
              (i32.add)
              (local.get 16)
              (local.get 18)
              (i32.const 1)
              (i32.sub)
              (i32.const 1)
              (i32.mul)
              (i32.add)
              (i32.load8_u)
              (i32.store8)
              (local.get 18)
              (i32.const 1)
              (i32.sub)
              (local.set 18)
              (i32.const 0)
              (local.set 7)
              (local.set 8)
              (local.get 7)
              (local.get 8)
              (i32.store align=1)
              (br 1)
            )
            (else (nop))
          )
        )
        (i32.const 0)
      )
      (else
        (i32.const 32)
        (local.get 15)
        (local.get 2)
        (local.get 1)
        (i32.const 0)
        (i32.const 0)
        (call 9)
      )
    )
    (drop)
    (local.get 10)
    (local.set 19)
    (local.get 19)
    (call 8)
    (drop)
    (i32.const 0)
    (i32.load align=1)
    (local.get 10)
    (i32.const 1)
    (i32.mul)
    (i32.const 1)
    (i32.mul)
    (i32.const 0)
    (i32.load align=1)
    (i32.add)
    (call 4)
    (i32.const 0)
    (local.set 7)
    (local.set 8)
    (local.get 7)
    (local.get 8)
    (i32.store align=1)
    (local.set 20)
    (local.get 20)
    (i32.const 54)
    (i32.store8)
    (local.get 19)
    (i32.const 1)
    (i32.sub)
    (local.set 19)
    (loop
      (local.get 19)
      (i32.const 0)
      (i32.gt_u)
      (if
        (then
          (i32.const 0)
          (i32.load align=1)
          (local.get 20)
          (local.get 19)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (local.get 20)
          (i32.load8_u)
          (i32.store8)
          (local.get 19)
          (i32.const 1)
          (i32.sub)
          (local.set 19)
          (i32.const 0)
          (local.set 7)
          (local.set 8)
          (local.get 7)
          (local.get 8)
          (i32.store align=1)
          (br 1)
        )
        (else (nop))
      )
    )
    (local.get 20)
    (local.set 21)
    (i32.const 0)
    (local.set 22)
    (loop
      (local.get 22)
      (local.get 10)
      (i32.lt_u)
      (if
        (then
          (i32.const 0)
          (i32.load align=1)
          (local.get 21)
          (local.get 22)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (i32.load8_u)
          (local.set 23)
          (local.get 13)
          (local.get 22)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (i32.load8_u)
          (local.set 24)
          (local.get 21)
          (local.get 22)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (local.get 23)
          (local.get 24)
          (i32.xor)
          (i32.const 255)
          (i32.and)
          (i32.store8)
          (local.get 22)
          (i32.const 1)
          (i32.add)
          (local.set 22)
          (i32.const 0)
          (local.set 7)
          (local.set 8)
          (local.get 7)
          (local.get 8)
          (i32.store align=1)
          (br 1)
        )
        (else (nop))
      )
    )
    (local.get 10)
    (local.set 25)
    (local.get 25)
    (call 8)
    (drop)
    (i32.const 0)
    (i32.load align=1)
    (local.get 10)
    (i32.const 1)
    (i32.mul)
    (i32.const 1)
    (i32.mul)
    (i32.const 0)
    (i32.load align=1)
    (i32.add)
    (call 4)
    (i32.const 0)
    (local.set 7)
    (local.set 8)
    (local.get 7)
    (local.get 8)
    (i32.store align=1)
    (local.set 26)
    (local.get 26)
    (i32.const 92)
    (i32.store8)
    (local.get 25)
    (i32.const 1)
    (i32.sub)
    (local.set 25)
    (loop
      (local.get 25)
      (i32.const 0)
      (i32.gt_u)
      (if
        (then
          (i32.const 0)
          (i32.load align=1)
          (local.get 26)
          (local.get 25)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (local.get 26)
          (i32.load8_u)
          (i32.store8)
          (local.get 25)
          (i32.const 1)
          (i32.sub)
          (local.set 25)
          (i32.const 0)
          (local.set 7)
          (local.set 8)
          (local.get 7)
          (local.get 8)
          (i32.store align=1)
          (br 1)
        )
        (else (nop))
      )
    )
    (local.get 26)
    (local.set 27)
    (i32.const 0)
    (local.set 28)
    (loop
      (local.get 28)
      (local.get 10)
      (i32.lt_u)
      (if
        (then
          (i32.const 0)
          (i32.load align=1)
          (local.get 27)
          (local.get 28)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (i32.load8_u)
          (local.set 29)
          (local.get 13)
          (local.get 28)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (i32.load8_u)
          (local.set 30)
          (local.get 27)
          (local.get 28)
          (i32.const 1)
          (i32.mul)
          (i32.add)
          (local.get 29)
          (local.get 30)
          (i32.xor)
          (i32.const 255)
          (i32.and)
          (i32.store8)
          (local.get 28)
          (i32.const 1)
          (i32.add)
          (local.set 28)
          (i32.const 0)
          (local.set 7)
          (local.set 8)
          (local.get 7)
          (local.get 8)
          (i32.store align=1)
          (br 1)
        )
        (else (nop))
      )
    )
    (i32.const 4)
    (local.set 31)
    (global.get 0)
    (i32.const 0)
    (i32.add)
    (call 7)
    (unreachable)
    (local.get 9)
    (i32.const 0)
    (local.set 7)
    (local.set 8)
    (local.get 7)
    (local.get 8)
    (i32.store align=1)
  )
  (export "Hacl_HMAC_Blake2s_128_compute_blake2s_128" (func 10))
  (export "data_size" (global 1))
  (data $0
    (global.get 0)
    "\48\61\63\6c\2e\48\4d\41\43\2e\42\6c\61\6b\65\32"
    "\73\5f\31\32\38\2e\63\6f\6d\70\75\74\65\5f\62\6c"
    "\61\6b\65\32\73\5f\31\32\38\3a\20\63\6f\6d\70\69"
    "\6c\61\74\69\6f\6e\20\65\72\72\6f\72\20\74\75\72"
    "\6e\65\64\20\74\6f\20\72\75\6e\74\69\6d\65\20\66"
    "\61\69\6c\75\72\65\0a\46\61\69\6c\75\72\65\28\22"
    "\6d\69\73\73\69\6e\67\20\74\79\70\65\20\69\6e\20"
    "\6c\61\79\6f\75\74\20\6d\61\70\3a\20\4c\69\62\2e"
    "\49\6e\74\56\65\63\74\6f\72\2e\49\6e\74\72\69\6e"
    "\73\69\63\73\2e\76\65\63\31\32\38\22\29\00"
  )
)
