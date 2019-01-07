(* MaBo - MRT dumper
 * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
 *)


open Mrt
open Types
open Inputs
open Arg
open Yojson


(** Get the AS_PATH as a string *)
let rec get_aspath_str ?(space="") l =
  let rec p l  =
    match l with
    | ASN16(e)::lst
    | ASN32(e)::lst -> (Printf.sprintf "%lu" e)::(p lst)
    | [] -> []
  in
  (* Output as a SET or a SEQUENCE. *)
  match l with
  | AS_SET(e)::lst ->
      space ^ "{" ^ (Printers.join "," (p e)) ^ "}" ^ (get_aspath_str ~space:" " lst)
  | AS_SEQUENCE(e)::lst ->
      space ^ (Printers.join " " (p e)) ^ (get_aspath_str ~space:" " lst)
  | AS_CONFED_SET(e)::lst -> 
      space ^ "[" ^ (Printers.join " " (p e)) ^ "]" ^ (get_aspath_str ~space:" " lst)
  | AS_CONFED_SEQUENCE(e)::lst ->
      space ^ "(" ^ (Printers.join " " (p e)) ^ ")" ^ (get_aspath_str ~space:" " lst)
  | Unknown_AS_PATH_TYPE(n)::lst ->
      let message = Printf.sprintf "Unknown PATH type: %d ( parsing will likely stop here)" n in 
      space  ^ message ^ (get_aspath_str ~space:" " lst)
  | [] -> ""


(** Get AS_PATH attributes *)
let rec get_as_path l =
  (* Check if there is only one AS_PATH attribute. *)
  begin
  match List.length l with
  | 0 | 1 -> ()
  | n ->
    raise (MRTParsingError (Printf.sprintf "get_as_path(): don't know what to do with %d AS_PATH !\n" n ))
  end;

  (* Get the AS_PATH as a string. *)
  match l with
  | BGPAttributeAS4_PATH(_, path_segments)::lst 
  | BGPAttributeAS_PATH(_, path_segments)::lst -> 
      get_aspath_str path_segments

  | _::lst -> get_as_path lst

  | [] -> ""


(** Print the FROM line *)
let get_from46_peers peers p_i =
  match List.length peers with
  | n when n > p_i -> 
      begin
        let _,ipa,asn = List.nth peers p_i in
        match ipa with
        | IPv6(a) -> "F6", a, asn
        | IPv4(a) -> "F4", a, asn
        | UnknownIP(a) -> "", (Printf.sprintf "%d" a), asn
      end
  | _ -> "FN", "", 0l


let get_from46 ip asn =
  match ip with
  | IPv6(a)      -> "F6", a, asn
  | IPv4(a)      -> "F4", a, asn
  | UnknownIP(a) -> "FU", (Printf.sprintf "%d" a), asn


(** Get prefixes *)
let rec get_prefixes ?(type_str="") p =
  match p with
  | Prefix(IPv4(ip), plen)::lst -> let tmp = Printf.sprintf "%s4 %s %i" type_str ip plen in
                                   tmp::(get_prefixes ~type_str:type_str lst)
  | Prefix(IPv6(ip), plen)::lst -> let tmp = Printf.sprintf "%s6 %s %i" type_str ip plen in
                                   tmp::(get_prefixes ~type_str:type_str lst)
  | Prefix(UnknownIP(a), plen)::lst -> let tmp = Printf.sprintf "%su %i UNKNOWN_IP" type_str a in
                                       tmp::(get_prefixes ~type_str:type_str lst)
  | [] -> []


(** Get prefixes raw *)
let rec get_prefixes_raw ?(type_str="") p =
  match p with
  | Prefix(IPv4(ip), plen)::lst -> let tmp = Printf.sprintf "%s/%i" ip plen in
                                   tmp::(get_prefixes_raw lst)
  | Prefix(IPv6(ip), plen)::lst -> let tmp = Printf.sprintf "%s/%i" ip plen in
                                   tmp::(get_prefixes_raw lst)
  | Prefix(UnknownIP(a), plen)::lst -> let tmp = Printf.sprintf "UNKNOWN_IP/%i" a in
                                       tmp::(get_prefixes_raw lst)
  | [] -> []


(** Simple helper function *)
let rec print_prefixes prefixes_str_list =
  match prefixes_str_list with
  | str::lst -> (Printf.printf "%s\n" str; print_prefixes lst)
  | [] -> ()


(** Print TABLE_DUMP_v2 *)
let print_table_dump_v2 peers ts prefix l str_type = 
  let rec print_re l =
    match l with
    | RIBEntry(p_i, ts, _, rel)::lst ->
        begin
          let from_type, peer_ip, peer_as = get_from46_peers peers p_i in
          let tmp_str = Printf.sprintf "%s %s %lu %lu" from_type peer_ip peer_as ts in
          let tmp_ap = get_as_path (Printers.merge_as_path rel) in
          begin
            match tmp_ap with
            | "" -> Printf.printf "%s\n" tmp_str; (* Empty AS_PATH *)
            | _  -> Printf.printf "%s %s\n" tmp_str tmp_ap;
          end;
          print_re lst;
        end
    | [] -> ()
  in
    Printf.printf "%s %lu\n" str_type ts;
    print_prefixes (get_prefixes ~type_str:"P" [prefix]);
    print_re l;
    print_newline ()


(** Get IPv6 prefixes in an NLRI atttribute *)
let rec get_reach_nlri ?(get_prefixes = get_prefixes) attr =
  match attr with
  | BGPAttributeMP_REACH_NLRI(_, INET6, _, _, prefixes)::lst ->
      (get_prefixes ~type_str:"A" prefixes)@(get_reach_nlri ~get_prefixes:get_prefixes lst)
  | _::lst -> get_reach_nlri ~get_prefixes:get_prefixes lst
  | [] -> []

let rec get_unreach_nlri ?(get_prefixes = get_prefixes) attr =
  match attr with
  | BGPAttributeMP_UNREACH_NLRI(_, INET6, _, prefixes)::lst ->
      (get_prefixes ~type_str:"W" prefixes)@(get_unreach_nlri ~get_prefixes:get_prefixes lst)
  | _::lst -> get_unreach_nlri ~get_prefixes:get_prefixes lst
  | [] -> []


(** Print the MRT header *)
let print_mrt ?(peers = []) ?(pipe = false) hdr = 
  match hdr with

  | MRTHeader(ts, TABLE_DUMP(afi, vn, sn, prefix, td_ts, pi, pa, attr)) -> 
      Printf.eprintf "TABLE_DUMP is not supported in legacy mode\n"

  | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV4_UNICAST(_, prefix, l))) -> 
      print_table_dump_v2 peers ts prefix l "T4"

  | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV6_UNICAST(_, prefix, l))) ->
      print_table_dump_v2 peers ts prefix l "T6"

  | MRTHeader(ts, BGP4MP(MESSAGE(ASN16(pa), ASN16(_), _, pi, _, BGP_UPDATE(wr, attr, prefixes))))
  | MRTHeader(ts, BGP4MP(MESSAGE_AS4(ASN32(pa), ASN32(_), _, pi, _, BGP_UPDATE(wr, attr, prefixes)))) ->
                     (match List.length wr, List.length attr, List.length prefixes with
		     | 0, 0, 0 -> ()
		     | _, _, _ -> begin
                                  let from_type, peer_ip, peer_as = get_from46 pi pa in
                                  Printf.printf "UP %lu\n%s %s %lu\n" ts from_type peer_ip peer_as;
                                  let tmp_ap = get_as_path (Printers.merge_as_path attr) in
                                  begin
                                    match tmp_ap with
                                    | "" -> () (* Empty AS_PATH / withdraw only *)
                                    | _ -> Printf.printf "AP %s\n" tmp_ap
                                  end;
                                  print_prefixes (get_unreach_nlri attr); (* IPv6 only *)
                                  print_prefixes (get_reach_nlri attr);   (* IPv6 only *)
                                  print_prefixes (get_prefixes ~type_str:"W" wr);
                                  print_prefixes (get_prefixes ~type_str:"A" prefixes);
                                  print_newline ()
                                  end)

  | MRTHeader(_, _) -> if pipe then print_newline () else ()


(** Ease the transformation of PEER IP, PEER AS et AS PATH *)
let re2json peers p_i rel =
  let _, peer_ip, peer_as = get_from46_peers peers p_i in 
  let as_path = get_as_path (Printers.merge_as_path rel) in
  peer_ip,peer_as,as_path


(** Transform a RIBEntry list to JSON *)
let rec rel2json peers rel =
  match rel with
  | RIBEntry(p_i, ts, _, rel)::lst -> 
      begin
        let peer_ip,peer_as,as_path = re2json peers p_i rel in
        let re_json = [ ("peer_ip", `String(peer_ip));
                        ("peer_as", `Float(Int32.to_float peer_as));
                        ("originated_timestamp", `Float(Int32.to_float ts));
                        ("as_path", `String(as_path)) ] in
        `Assoc(re_json)::(rel2json peers lst)
      end
  | [] -> []


(** Transform a TABLE_DUMP_v2 to JSON *)
let table_dump2json peers ts prefix re_list = 
  (* Prepare the common "header" *)
  let tmp_prefix = match prefix with
                   | Prefix(UnknownIP(_), plen) -> "UNKNOWN_IP"
                   | Prefix(IPv4(ip), plen)
                   | Prefix(IPv6(ip), plen) ->
                       Printf.sprintf "%s/%d" ip plen in
  let tmp_json = [ ("type", `String("table_dump_v2"));
                   ("timestamp", `Float(Int32.to_float ts));
                   ("prefix", `String(tmp_prefix)) ] in
  (* Parse the RIB entries *)
  let re_list = `List(rel2json peers re_list) in
  `Assoc(("entries", re_list)::tmp_json)


(** Transform an UPDATE to JSON *)
let update2json ?(msg_type="update") ts peer_as peer_ip withdraw attr prefixes =

  (* Get the AS_PATH *)
  let as_path = match get_as_path (Printers.merge_as_path attr) with
                | "" -> []
                | ap -> [("as_path", `String(ap))] in

  (* Prepare the common "header" *)
  let tmp_json = [ ("type", `String(msg_type));
                   ("timestamp", `Float(Int32.to_float ts));
                   ("peer_as", `Float(Int32.to_float peer_as));
                   ("peer_ip", `String(peer_ip)) ] @ as_path in


  (* Retrieve withdraws & announces *)
  let str2yojsonstring = List.map (fun prefix -> `String(prefix)) in
  let wr_ipv6 = str2yojsonstring (get_unreach_nlri ~get_prefixes:get_prefixes_raw attr) (* IPv6 only *)
  and up_ipv6 = str2yojsonstring (get_reach_nlri ~get_prefixes:get_prefixes_raw attr)   (* IPv6 only *)
  and wr_ipv4 = str2yojsonstring (get_prefixes_raw withdraw)
  and up_ipv4 = str2yojsonstring (get_prefixes_raw prefixes)  in

  (* Return the UPDATE *)
  let withdraw_json = `List(wr_ipv6@wr_ipv4) in
  let announce_json = `List(up_ipv6@up_ipv4) in
  match msg_type with
  | "table_dump" -> `Assoc(tmp_json@[("announce", announce_json)])
  | _           -> `Assoc(tmp_json@[("announce", announce_json);("withdraw", withdraw_json)]) 

let get_state_string = function
  | Idle -> "idle"
  | Connect -> "connect"
  | Active -> "active"
  | OpenSent -> "open_sent"
  | OpenConfirm -> "open_confirm"
  | Established -> "established"
  | FSM_STATE_UNKNOWN n -> Printf.sprintf "unknown (%d)" n


(** Transform a STATE_CHANGE to JSON **)
let state_change2json ts peer_as peer_ip old_state new_state =
  let tmp_json = [ ("type", `String("state_change"));
                   ("timestamp", `Float(Int32.to_float ts));
                   ("peer_as", `Float(Int32.to_float peer_as));
                   ("peer_ip", `String(peer_ip));
                   ("old_state", `String(get_state_string old_state));
                   ("new_state", `String(get_state_string new_state)) ] in
  `Assoc(tmp_json)


let print_mrt_json ?(peers = []) ?(pipe = false) hdr =
  match hdr with
  | MRTHeader(ts, TABLE_DUMP(_, _, _, prefix, td_ts, pi, pa, attr)) -> 
      let _, peer_ip, peer_as = get_from46 pi pa in
      let json = update2json ~msg_type:"table_dump" td_ts peer_as peer_ip [] attr [prefix] in
      Printf.printf "%s\n" (Yojson.to_string json)
  | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV4_UNICAST(_, prefix, l))) -> 
      Printf.printf "%s\n" (Yojson.to_string (table_dump2json peers ts prefix l))
  | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV6_UNICAST(_, prefix, l))) -> 
      Printf.printf "%s\n" (Yojson.to_string (table_dump2json peers ts prefix l))
  | MRTHeader(ts, BGP4MP(MESSAGE(ASN16(pa), ASN16(_), _, pi, _, BGP_UPDATE(wr, attr, prefixes))))
  | MRTHeader(ts, BGP4MP(MESSAGE_AS4(ASN32(pa), ASN32(_), _, pi, _, BGP_UPDATE(wr, attr, prefixes)))) ->
      let from_type, peer_ip, peer_as = get_from46 pi pa in
      let json = update2json ts peer_as peer_ip wr attr prefixes in
      Printf.printf "%s\n" (Yojson.to_string json)
  | MRTHeader(ts, BGP4MP(STATE_CHANGE(ASN16(pa), _, _, _, pi, _, os, ns)))
  | MRTHeader(ts, BGP4MP(STATE_CHANGE_AS4(ASN32(pa), _, _, _, pi, _, os, ns))) ->
      let from_type, peer_ip, peer_as = get_from46 pi pa in
      let json = state_change2json ts peer_as peer_ip os ns in
      Printf.printf "%s\n" (Yojson.to_string json)
  | MRTHeader(_, _) -> if pipe then print_newline () else ()


(** Main loop *)
let parsing_loop m filename do_json do_unknown =
  let module Mrt = MrtParser ((val m : InputRaw)) in
  let pc = Mrt.Input.create filename
  and count_headers = ref 0
  and peers = ref [] in
  try
    while true
    do
      try
	begin
	let hdr = Mrt.mrt_hdr pc
        in
          (match do_unknown with
           | true  -> Mrt.show_unknown hdr
           | false -> (match hdr with
                       | MRTHeader(ts,
                                   TABLE_DUMP_v2(PEER_INDEX_TABLE(bgpid,
                                                                  viewname, l)))
                                     -> peers := Printers.get_peers l
                | _ -> begin
                         (* Legacy output or JSON *)
                         match do_json with
                         | false -> print_mrt ~peers:!peers hdr
                         | true  -> print_mrt_json ~peers:!peers hdr
                       end;
                       flush stdout)
           )
	end;
	count_headers := (!count_headers) + 1;
      with
      | MRTParsingError(m) -> Printf.eprintf "MRT parsing error: %s\n" m
    done
  with
  | End_of_file -> ()


(** Main loop for the pipe mode *)

(* The following binary format is expected on stdin:
   - command (1 byte)
   - length  (4 bytes)
   - index   (4 bytes)
   - data    ('length' bytes): it must contain an MRT dump
  Each MRT dump is processed, then display on stdout as well as the index.
 *)

let parsing_pipe json =
  let ms = (module InputString: InputRaw) in
  let module MrtString = MrtParser ((val ms : InputRaw)) in

  (* Ease the parsing of MRT dumps from a string *)
  let _str_parser str index peers headers =
    let pc = MrtString.Input.create str in
    try
      begin
      let hdr = MrtString.mrt_hdr pc in
      match hdr with
      | MRTHeader(ts, TABLE_DUMP_v2(PEER_INDEX_TABLE(bgpid, viewname, l))) ->
             peers := Printers.get_peers l
      | _ -> begin
             Printf.printf "ID %ld\n" index;
             (* Legacy output or JSON *)
             begin
               match json with
               | false -> print_mrt ~peers:!peers hdr
               | true  -> print_mrt_json ~peers:!peers hdr
             end;
             if json then print_newline () else ()
             end
      end;
      headers := (!headers) + 1;
    with
    | MRTParsingError(m) -> Printf.eprintf "ERROR: MRT parsing error: %s\n" m
    | End_of_file -> Printf.eprintf "ERROR: MRT Parsing error: dump seems invalid ! (%s)\n" (MrtTools.string_to_hexa str)

  (* Check the header *)
  and _check_header hdr previous_index =
    let pc = MrtString.Input.create hdr in
    let command = MrtString.Input.get_byte pc in
    let len = Int32.to_int (MrtString.Input.get_int32 pc) in
    let index = MrtString.Input.get_int32 pc in

    (* Is the index valid ? *)
    match index >= previous_index with
    | false -> begin
	       Printf.printf "ERROR-FATAL: index is smaller than the previous one %ld < %ld\n" index previous_index;
	       raise End_of_file
	       end;
    | true -> ();

    (* Is it a valid command ? *)
    match command with
    | 0
    | 1 -> (command, len, index)
    | n -> begin
	   Printf.printf "ERROR-FATAL: Unknown command %d\n" n;
	   raise End_of_file
	   end;

  in

  let fd = Unix.stdin
  and previous_index = ref 0l
  and count_headers = ref 0
  and peers = ref [] in

  try 
    while true
    do
      (* Wait for data *)
      match Unix.select [fd] [] [] (-1.0) with
      | [], _, _ -> ()
      | read, _, _ -> begin
                      (* 1. get the header *)
                      let header = Bytes.create 9 in
		      let bytes = Unix.read fd header 0 9 in
		      (if bytes <> 9
		      then
		        (Printf.printf "ERROR-FATAL: header - not enough data %d/%d\n" bytes 9;
			raise End_of_file));
                      
                      (* 2. check the header *)
		      let cmd,len,index = _check_header (Bytes.to_string header) !previous_index in
		      previous_index := index;

		      if cmd = 1 (* the exit code *)
		      then
		        (Printf.printf "END\n\n";
		         raise End_of_file);

		      (* 3. parse the MRT dump *)
		      let rec _read_exact fd len_needed =
		        let tmp = Bytes.create len_needed in
			let bytes = Unix.read fd tmp 0 len_needed in
			match bytes = len_needed with
			| true  -> bytes,tmp
			| false -> let tmp_len = len_needed-bytes in
			           let b,t = _read_exact fd tmp_len in
			           bytes+b, tmp
			           
		      in
		      let bytes,tmp = _read_exact fd len in

		      (if bytes <> len
		      then
		        (Printf.printf "ERROR-FATAL: MRT dump - not enough data %d/%d\n" bytes len;
			raise End_of_file));
                      _str_parser (Bytes.to_string tmp) index peers count_headers;

		      end;
    done
  with
  | End_of_file -> ()

 
(** Load the MRT dump *)
let has_extension fname ext =
   let ext_len = String.length ext in
  (String.sub fname ((String.length fname)-ext_len) ext_len) = ext


(** Define the main function *)
let main previous_usage args_array =
  (* Define program parameters & command line arguments *)
  let mrt_filename = ref ""
  and do_pipe = ref false
  and do_json = ref true
  and do_unknown = ref false
  and usage_dump = " dump [--legacy] [--pipe] mrt.dump
  
Dump the content of a MRT file

Arguments:
  mrt.dump               a MRT dump

Optional arguments:
  --legacy              dump MRT files like bgpdump
  --unknown             display unknown MRT & BGP messages types
  --pipe                special mode to communicate with the sub-command with stdin & stdout\n" in
  let usage = previous_usage ^ usage_dump in
  let arguments = [ ("--pipe", Unit(fun x -> do_pipe := true), "");
                    ("--unknown", Unit(fun x -> do_unknown := true), "");
                    ("--legacy", Unit(fun x -> do_json := false), "") ] in

  (* Parse command lines arguments *)
  let args_length = Array.length args_array in
  match args_length with
    | 0 | 1 -> (Printf.printf "%s" usage; exit 1)
    | _ -> ();

  begin
    try
      Arg.parse_argv args_array arguments
                     (fun x -> match String.length !mrt_filename with 0 -> mrt_filename := x |  _ -> ())
                     usage
    with
    | Arg.Bad(_) -> (Printf.printf "%s" usage; exit 1)
    | _ -> ()
  end;

  (* Check arguments usage. *)
  let len_mrt = String.length !mrt_filename in

  (* Parse a file or stdin *)
  if len_mrt = 0 && !do_pipe = false
  then
     (Printf.eprintf "%s" usage; exit 1);

  if len_mrt > 0 && !do_pipe
  then
    (Printf.eprintf "Error: --pipe can't be used when specifying a filename !\n";
     Printf.eprintf "%s" usage; exit 1);


  (* Parse the MRT dump *)
  match !do_pipe with
  | false -> (* Parse a regular file *)
             begin
             let m = choose_module !mrt_filename in
               parsing_loop m !mrt_filename !do_json !do_unknown
             end
  | true -> (* Interact with stdin and stdout *)
            parsing_pipe !do_json
