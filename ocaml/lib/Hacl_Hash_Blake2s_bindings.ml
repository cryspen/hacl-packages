open Ctypes
module Bindings(F:Cstubs.FOREIGN) =
  struct
    open F
    module Hacl_Streaming_Types_applied =
      (Hacl_Streaming_Types_bindings.Bindings)(Hacl_Streaming_Types_stubs)
    open Hacl_Streaming_Types_applied
    let hacl_Hash_Blake2s_init =
      foreign "Hacl_Hash_Blake2s_init"
        ((ptr uint32_t) @-> (uint32_t @-> (uint32_t @-> (returning void))))
    let hacl_Hash_Blake2s_update_multi =
      foreign "Hacl_Hash_Blake2s_update_multi"
        (uint32_t @->
           ((ptr uint32_t) @->
              ((ptr uint32_t) @->
                 (uint64_t @->
                    (ocaml_bytes @-> (uint32_t @-> (returning void)))))))
    let hacl_Hash_Blake2s_update_last =
      foreign "Hacl_Hash_Blake2s_update_last"
        (uint32_t @->
           ((ptr uint32_t) @->
              ((ptr uint32_t) @->
                 (uint64_t @->
                    (uint32_t @-> (ocaml_bytes @-> (returning void)))))))
    let hacl_Hash_Blake2s_finish =
      foreign "Hacl_Hash_Blake2s_finish"
        (uint32_t @-> (ocaml_bytes @-> ((ptr uint32_t) @-> (returning void))))
    type hacl_Hash_Blake2s_block_state_t =
      [ `hacl_Hash_Blake2s_block_state_t ] structure
    let (hacl_Hash_Blake2s_block_state_t :
      [ `hacl_Hash_Blake2s_block_state_t ] structure typ) =
      structure "Hacl_Hash_Blake2s_block_state_t_s"
    let hacl_Hash_Blake2s_block_state_t_fst =
      field hacl_Hash_Blake2s_block_state_t "fst" (ptr uint32_t)
    let hacl_Hash_Blake2s_block_state_t_snd =
      field hacl_Hash_Blake2s_block_state_t "snd" (ptr uint32_t)
    let _ = seal hacl_Hash_Blake2s_block_state_t
    type hacl_Hash_Blake2s_state_t = [ `hacl_Hash_Blake2s_state_t ] structure
    let (hacl_Hash_Blake2s_state_t :
      [ `hacl_Hash_Blake2s_state_t ] structure typ) =
      structure "Hacl_Hash_Blake2s_state_t_s"
    let hacl_Hash_Blake2s_state_t_block_state =
      field hacl_Hash_Blake2s_state_t "block_state"
        hacl_Hash_Blake2s_block_state_t
    let hacl_Hash_Blake2s_state_t_buf =
      field hacl_Hash_Blake2s_state_t "buf" (ptr uint8_t)
    let hacl_Hash_Blake2s_state_t_total_len =
      field hacl_Hash_Blake2s_state_t "total_len" uint64_t
    let _ = seal hacl_Hash_Blake2s_state_t
    let hacl_Hash_Blake2s_malloc =
      foreign "Hacl_Hash_Blake2s_malloc"
        (void @-> (returning (ptr hacl_Hash_Blake2s_state_t)))
    let hacl_Hash_Blake2s_reset =
      foreign "Hacl_Hash_Blake2s_reset"
        ((ptr hacl_Hash_Blake2s_state_t) @-> (returning void))
    let hacl_Hash_Blake2s_update =
      foreign "Hacl_Hash_Blake2s_update"
        ((ptr hacl_Hash_Blake2s_state_t) @->
           (ocaml_bytes @->
              (uint32_t @-> (returning hacl_Streaming_Types_error_code))))
    let hacl_Hash_Blake2s_digest =
      foreign "Hacl_Hash_Blake2s_digest"
        ((ptr hacl_Hash_Blake2s_state_t) @->
           (ocaml_bytes @-> (returning void)))
    let hacl_Hash_Blake2s_free =
      foreign "Hacl_Hash_Blake2s_free"
        ((ptr hacl_Hash_Blake2s_state_t) @-> (returning void))
    let hacl_Hash_Blake2s_hash_with_key =
      foreign "Hacl_Hash_Blake2s_hash_with_key"
        (ocaml_bytes @->
           (uint32_t @->
              (ocaml_bytes @->
                 (uint32_t @->
                    (ocaml_bytes @-> (uint32_t @-> (returning void)))))))
  end