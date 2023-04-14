(module
  (type $0 (func (param i64) (result i64)))
  (type $1 (func (param i64) (result i32 i32)))
  (type $2 (func (param i32) (result i32)))
  (type $3 (func (param i32) (result i32)))
  (type $4 (func (param i32) (result i32)))
  (type $5 (func (param i32) (result i32)))
  (type $6 (func (param i32) (result i32)))
  (type $7 (func (param i32) (result i32)))
  (type $8 (func (param i32 i32 i32) (result i32)))
  (type $9 (func (param i32 i32 i64 i32) (result i64)))
  (import "Karamel" "mem" (memory $0 16))
  (import "WasmSupport" "WasmSupport_betole64" (func $0 (type 0)))
  (import "WasmSupport" "WasmSupport_betole64_packed" (func $1 (type 1)))
  (import "WasmSupport" "WasmSupport_align_64" (func $2 (type 2)))
  (import "WasmSupport" "WasmSupport_malloc" (func $3 (type 3)))
  (import "WasmSupport" "WasmSupport_betole32" (func $4 (type 4)))
  (import "WasmSupport" "WasmSupport_trap" (func $5 (type 5)))
  (import "WasmSupport" "WasmSupport_betole16" (func $6 (type 6)))
  (import "WasmSupport" "WasmSupport_check_buffer_size" (func $7 (type 7)))
  (import "WasmSupport" "WasmSupport_memzero" (func $8 (type 8)))
  (import "Karamel" "data_start" (global $0 i32))
  (global $1 i32 (i32.const 139))
  (func $9
    (type 9)
    (local i64 i64 i32 i32 i32)
    (i32.const 0)
    (i32.load align=1)
    (local.set 8)
    (global.get 0)
    (i32.const 0)
    (i32.add)
    (call 5)
    (unreachable)
    (local.get 8)
    (i32.const 0)
    (local.set 6)
    (local.set 7)
    (local.get 6)
    (local.get 7)
    (i32.store align=1)
  )
  (export "sha256_update" (func 9))
  (export "data_size" (global 1))
  (data $0
    (global.get 0)
    "\41\62\6f\72\74\3a\20\73\68\61\32\35\36\5f\75\70"
    "\64\61\74\65\20\77\61\73\20\6d\65\61\6e\74\20\74"
    "\6f\20\62\65\20\68\61\6e\64\2d\77\72\69\74\74\65"
    "\6e\20\61\6e\64\20\70\72\6f\76\69\64\65\64\20\61"
    "\74\20\6c\69\6e\6b\2d\74\69\6d\65\2c\20\62\75\74"
    "\20\63\6f\6e\74\61\69\6e\73\20\61\6e\20\49\36\34"
    "\20\61\6e\64\20\74\68\65\72\65\66\6f\72\65\20\63"
    "\61\6e\6e\6f\74\20\62\65\20\63\61\6c\6c\65\64\20"
    "\66\72\6f\6d\20\57\41\53\4d\2e\00"
  )
)
