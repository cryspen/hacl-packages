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
  (global $1 i32 (i32.const 64))
  (global $2 i32 (i32.const 32))
  (global $3 i32 (i32.const 0))
  (export "FStar_UInt128_u32_64" (global 1))
  (export "FStar_UInt128_u32_32" (global 2))
  (export "data_size" (global 3))
  (data $0 (global.get 0))
)
