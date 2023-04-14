(module
  (type $0 (func (param i64) (result i64)))
  (type $1 (func (param i32) (result i32)))
  (type $2 (func (param i32) (result i32)))
  (type $3 (func (param i32) (result i32)))
  (type $4 (func (param i64) (result i32 i32)))
  (type $5 (func (param i32) (result i32)))
  (type $6 (func (param i32) (result i32)))
  (type $7 (func (param i32) (result i32)))
  (type $8 (func (param i32 i32 i32) (result i32)))
  (type $9 (func (param i32) (result i32)))
  (type $10 (func (param i32) (result i32)))
  (type $11 (func (param i32) (result i32)))
  (type $12 (func (param i32) (result i32)))
  (type $13 (func (param i32) (result i32)))
  (type $14 (func (param i32) (result i32)))
  (type $15 (func))
  (import "Karamel" "mem" (memory $0 16))
  (import "WasmSupport" "WasmSupport_betole64" (func $0 (type 0)))
  (import "WasmSupport" "WasmSupport_align_64" (func $1 (type 1)))
  (import "WasmSupport" "WasmSupport_malloc" (func $2 (type 2)))
  (import "WasmSupport" "WasmSupport_betole32" (func $3 (type 3)))
  (import "WasmSupport" "WasmSupport_betole64_packed" (func $4 (type 4)))
  (import "WasmSupport" "WasmSupport_trap" (func $5 (type 5)))
  (import "WasmSupport" "WasmSupport_betole16" (func $6 (type 6)))
  (import "WasmSupport" "WasmSupport_check_buffer_size" (func $7 (type 7)))
  (import "WasmSupport" "WasmSupport_memzero" (func $8 (type 8)))
  (import "Karamel" "data_start" (global $0 i32))
  (global $1 (mut i32) (i32.const 0))
  (global $2 (mut i32) (i32.const 0))
  (global $3 (mut i32) (i32.const 0))
  (global $4 (mut i32) (i32.const 0))
  (global $5 (mut i32) (i32.const 0))
  (global $6 (mut i32) (i32.const 0))
  (global $7 i32 (i32.const 1_094))
  (func $9
    (type 9)
    (local i64 i64 i32 i32 i32)
    (i32.const 0)
    (i32.load align=1)
    (local.set 5)
    (global.get 1)
    (local.get 5)
    (i32.const 0)
    (local.set 3)
    (local.set 4)
    (local.get 3)
    (local.get 4)
    (i32.store align=1)
  )
  (func $10
    (type 10)
    (local i64 i64 i32 i32 i32)
    (i32.const 0)
    (i32.load align=1)
    (local.set 5)
    (global.get 2)
    (local.get 5)
    (i32.const 0)
    (local.set 3)
    (local.set 4)
    (local.get 3)
    (local.get 4)
    (i32.store align=1)
  )
  (func $11
    (type 11)
    (local i64 i64 i32 i32 i32)
    (i32.const 0)
    (i32.load align=1)
    (local.set 5)
    (global.get 3)
    (local.get 5)
    (i32.const 0)
    (local.set 3)
    (local.set 4)
    (local.get 3)
    (local.get 4)
    (i32.store align=1)
  )
  (func $12
    (type 12)
    (local i64 i64 i32 i32 i32)
    (i32.const 0)
    (i32.load align=1)
    (local.set 5)
    (global.get 4)
    (local.get 5)
    (i32.const 0)
    (local.set 3)
    (local.set 4)
    (local.get 3)
    (local.get 4)
    (i32.store align=1)
  )
  (func $13
    (type 13)
    (local i64 i64 i32 i32 i32)
    (i32.const 0)
    (i32.load align=1)
    (local.set 5)
    (global.get 5)
    (local.get 5)
    (i32.const 0)
    (local.set 3)
    (local.set 4)
    (local.get 3)
    (local.get 4)
    (i32.store align=1)
  )
  (func $14
    (type 14)
    (local i64 i64 i32 i32 i32)
    (i32.const 0)
    (i32.load align=1)
    (local.set 5)
    (global.get 6)
    (local.get 5)
    (i32.const 0)
    (local.set 3)
    (local.set 4)
    (local.get 3)
    (local.get 4)
    (i32.store align=1)
  )
  (func $15
    (type 15)
    (global.get 0)
    (i32.const 0)
    (i32.add)
    (global.set 1)
    (global.get 0)
    (i32.const 33)
    (i32.add)
    (global.set 2)
    (global.get 0)
    (i32.const 66)
    (i32.add)
    (global.set 3)
    (global.get 0)
    (i32.const 131)
    (i32.add)
    (global.set 4)
    (global.get 0)
    (i32.const 196)
    (i32.add)
    (global.set 5)
    (global.get 0)
    (i32.const 453)
    (i32.add)
    (global.set 6)
  )
  (export "Hacl_Impl_SHA2_Generic___get_h224" (func 9))
  (export "Hacl_Impl_SHA2_Generic___get_h256" (func 10))
  (export "Hacl_Impl_SHA2_Generic___get_h384" (func 11))
  (export "Hacl_Impl_SHA2_Generic___get_h512" (func 12))
  (export "Hacl_Impl_SHA2_Generic___get_k224_256" (func 13))
  (export "Hacl_Impl_SHA2_Generic___get_k384_512" (func 14))
  (export "data_size" (global 7))
  (start 15)
  (data $0
    (global.get 0)
    "\d8\9e\05\c1\07\d5\7c\36\17\dd\70\30\39\59\0e\f7"
    "\31\0b\c0\ff\11\15\58\68\a7\8f\f9\64\a4\4f\fa\be"
    "\00\67\e6\09\6a\85\ae\67\bb\72\f3\6e\3c\3a\f5\4f"
    "\a5\7f\52\0e\51\8c\68\05\9b\ab\d9\83\1f\19\cd\e0"
    "\5b\00\d8\9e\05\c1\5d\9d\bb\cb\07\d5\7c\36\2a\29"
    "\9a\62\17\dd\70\30\5a\01\59\91\39\59\0e\f7\d8\ec"
    "\2f\15\31\0b\c0\ff\67\26\33\67\11\15\58\68\87\4a"
    "\b4\8e\a7\8f\f9\64\0d\2e\0c\db\a4\4f\fa\be\1d\48"
    "\b5\47\00\08\c9\bc\f3\67\e6\09\6a\3b\a7\ca\84\85"
    "\ae\67\bb\2b\f8\94\fe\72\f3\6e\3c\f1\36\1d\5f\3a"
    "\f5\4f\a5\d1\82\e6\ad\7f\52\0e\51\1f\6c\3e\2b\8c"
    "\68\05\9b\6b\bd\41\fb\ab\d9\83\1f\79\21\7e\13\19"
    "\cd\e0\5b\00\98\2f\8a\42\91\44\37\71\cf\fb\c0\b5"
    "\a5\db\b5\e9\5b\c2\56\39\f1\11\f1\59\a4\82\3f\92"
    "\d5\5e\1c\ab\98\aa\07\d8\01\5b\83\12\be\85\31\24"
    "\c3\7d\0c\55\74\5d\be\72\fe\b1\de\80\a7\06\dc\9b"
    "\74\f1\9b\c1\c1\69\9b\e4\86\47\be\ef\c6\9d\c1\0f"
    "\cc\a1\0c\24\6f\2c\e9\2d\aa\84\74\4a\dc\a9\b0\5c"
    "\da\88\f9\76\52\51\3e\98\6d\c6\31\a8\c8\27\03\b0"
    "\c7\7f\59\bf\f3\0b\e0\c6\47\91\a7\d5\51\63\ca\06"
    "\67\29\29\14\85\0a\b7\27\38\21\1b\2e\fc\6d\2c\4d"
    "\13\0d\38\53\54\73\0a\65\bb\0a\6a\76\2e\c9\c2\81"
    "\85\2c\72\92\a1\e8\bf\a2\4b\66\1a\a8\70\8b\4b\c2"
    "\a3\51\6c\c7\19\e8\92\d1\24\06\99\d6\85\35\0e\f4"
    "\70\a0\6a\10\16\c1\a4\19\08\6c\37\1e\4c\77\48\27"
    "\b5\bc\b0\34\b3\0c\1c\39\4a\aa\d8\4e\4f\ca\9c\5b"
    "\f3\6f\2e\68\ee\82\8f\74\6f\63\a5\78\14\78\c8\84"
    "\08\02\c7\8c\fa\ff\be\90\eb\6c\50\a4\f7\a3\f9\be"
    "\f2\78\71\c6\00\22\ae\28\d7\98\2f\8a\42\cd\65\ef"
    "\23\91\44\37\71\2f\3b\4d\ec\cf\fb\c0\b5\bc\db\89"
    "\81\a5\db\b5\e9\38\b5\48\f3\5b\c2\56\39\19\d0\05"
    "\b6\f1\11\f1\59\9b\4f\19\af\a4\82\3f\92\18\81\6d"
    "\da\d5\5e\1c\ab\42\02\03\a3\98\aa\07\d8\be\6f\70"
    "\45\01\5b\83\12\8c\b2\e4\4e\be\85\31\24\e2\b4\ff"
    "\d5\c3\7d\0c\55\6f\89\7b\f2\74\5d\be\72\b1\96\16"
    "\3b\fe\b1\de\80\35\12\c7\25\a7\06\dc\9b\94\26\69"
    "\cf\74\f1\9b\c1\d2\4a\f1\9e\c1\69\9b\e4\e3\25\4f"
    "\38\86\47\be\ef\b5\d5\8c\8b\c6\9d\c1\0f\65\9c\ac"
    "\77\cc\a1\0c\24\75\02\2b\59\6f\2c\e9\2d\83\e4\a6"
    "\6e\aa\84\74\4a\d4\fb\41\bd\dc\a9\b0\5c\b5\53\11"
    "\83\da\88\f9\76\ab\df\66\ee\52\51\3e\98\10\32\b4"
    "\2d\6d\c6\31\a8\3f\21\fb\98\c8\27\03\b0\e4\0e\ef"
    "\be\c7\7f\59\bf\c2\8f\a8\3d\f3\0b\e0\c6\25\a7\0a"
    "\93\47\91\a7\d5\6f\82\03\e0\51\63\ca\06\70\6e\0e"
    "\0a\67\29\29\14\fc\2f\d2\46\85\0a\b7\27\26\c9\26"
    "\5c\38\21\1b\2e\ed\2a\c4\5a\fc\6d\2c\4d\df\b3\95"
    "\9d\13\0d\38\53\de\63\af\8b\54\73\0a\65\a8\b2\77"
    "\3c\bb\0a\6a\76\e6\ae\ed\47\2e\c9\c2\81\3b\35\82"
    "\14\85\2c\72\92\64\03\f1\4c\a1\e8\bf\a2\01\30\42"
    "\bc\4b\66\1a\a8\91\97\f8\d0\70\8b\4b\c2\30\be\54"
    "\06\a3\51\6c\c7\18\52\ef\d6\19\e8\92\d1\10\a9\65"
    "\55\24\06\99\d6\2a\20\71\57\85\35\0e\f4\b8\d1\bb"
    "\32\70\a0\6a\10\c8\d0\d2\b8\16\c1\a4\19\53\ab\41"
    "\51\08\6c\37\1e\99\eb\8e\df\4c\77\48\27\a8\48\9b"
    "\e1\b5\bc\b0\34\63\5a\c9\c5\b3\0c\1c\39\cb\8a\41"
    "\e3\4a\aa\d8\4e\73\e3\63\77\4f\ca\9c\5b\a3\b8\b2"
    "\d6\f3\6f\2e\68\fc\b2\ef\5d\ee\82\8f\74\60\2f\17"
    "\43\6f\63\a5\78\72\ab\f0\a1\14\78\c8\84\ec\39\64"
    "\1a\08\02\c7\8c\28\1e\63\23\fa\ff\be\90\e9\bd\82"
    "\de\eb\6c\50\a4\15\79\c6\b2\f7\a3\f9\be\2b\53\72"
    "\e3\f2\78\71\c6\9c\61\26\ea\ce\3e\27\ca\07\c2\c0"
    "\21\c7\b8\86\d1\1e\eb\e0\cd\d6\7d\da\ea\78\d1\6e"
    "\ee\7f\4f\7d\f5\ba\6f\17\72\aa\67\f0\06\a6\98\c8"
    "\a2\c5\7d\63\0a\ae\0d\f9\be\04\98\3f\11\1b\47\1c"
    "\13\35\0b\71\1b\84\7d\04\23\f5\77\db\28\93\24\c7"
    "\40\7b\ab\ca\32\bc\be\c9\15\0a\be\9e\3c\4c\0d\10"
    "\9c\c4\67\1d\43\b6\42\3e\cb\be\d4\c5\4c\2a\7e\65"
    "\fc\9c\29\7f\59\ec\fa\d6\3a\ab\6f\cb\5f\17\58\47"
    "\4a\8c\19\44\6c\00"
  )
)
