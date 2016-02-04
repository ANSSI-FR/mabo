(* MaBo - use inet_* functions from C
 * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
 *)

module Socket =
struct
  type af_type = AF_INET | AF_INET6

  external inet_aton : string -> string = "ocaml_inet_aton"
  external inet_ntoa : string -> string = "ocaml_inet_ntoa"

  external inet_pton : af_type -> string -> string = "ocaml_inet_pton"
  external inet_ntop : af_type -> string -> string = "ocaml_inet_ntop"
end
