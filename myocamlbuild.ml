open Ocamlbuild_plugin

;;

dispatch begin function
| After_rules ->
  dep  ["link"; "ocaml"; "use_socket"] ["src/libsocket.a"];
| _ -> ()
end
