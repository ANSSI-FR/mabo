(* MaBo - get prefixes associated to a given list of ASN
 * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
 *)


open Mrt
open Inputs
open Types
open Printers
open Arg


(** asn list to an int32 list *) 
let rec aspath_to_list lap =
    let rec ap l =
      match l with
      | ASN16(e)::lst 
      | ASN32(e)::lst -> e::(ap lst)
      | [] -> []
    in
    match lap with
    | AS_SEQUENCE(e)::lst          
    | AS_SET(e)::lst 
    | AS_CONFED_SEQUENCE(e)::lst          
    | AS_CONFED_SET(e)::lst        -> (ap e)@(aspath_to_list lst)
    | Unknown_AS_PATH_TYPE(n)::lst -> aspath_to_list lst
    | [] -> []


(** Check if an AS_PATH is originated from an ASN contained in asn_list *)
let rec find_asn_attr attr_list asn_list all =
    match attr_list with
    | BGPAttributeAS4_PATH(_, path_segments)::tl
    | BGPAttributeAS_PATH(_, path_segments)::tl ->
                  begin
		  let aspath_list = aspath_to_list path_segments in
                  let as_origin = List.hd (List.rev ([0l]@aspath_list)) in
		  match all || List.exists (fun x -> x = as_origin) asn_list with
		  | true -> Some(as_origin, aspath_list)
		  | false -> find_asn_attr tl asn_list all
		  end
    | _::tl -> find_asn_attr tl asn_list all
    | [] -> None


let rec find_asn_re re asn_list all =
  match re with
  | RIBEntry(p_i, ts,_, rel):: lst -> begin
                                      match find_asn_attr rel asn_list all with
                                      | None -> find_asn_re lst asn_list all
				      | Some(n) as s -> s
				      end
  
  | [] -> None


(** Get the two neighbors of an ASN. *)
let rec get_asn_neighbors ?(previous=0l) asn neighbors = 
  match neighbors with
  | n::lst when n = asn -> begin
                           match lst with
			   | h::l  -> [ previous; h  ]
			   | []    -> [ previous ]
			   end
  | n::lst -> get_asn_neighbors ~previous:n asn lst
  | [] -> [ ]


(** Get a list of ASN from a file. *)
let asn_from_file filename =
  let inc = open_in filename in
    let rec read_loop i =
      try
	let asn = (Int32.of_string (input_line i)) in
	asn::(read_loop i)
      with
      | End_of_file -> []
  in
    read_loop inc


(** Define the main function *)
let main previous_usage args_array =

  (* Define the arguments and fill the variables. *)
  let all = ref true
  and filename = ref ""
  and asn_filename = ref ""
  and usage_prefixes = " prefixes [--asn-list asn_list.txt] mrt.dump

List AS & prefixes in a MRT file

Arguments:
  mrt.dump               a MRT dump

Optional arguments:
  --asn-list            a text file containing ASN as integers\n" in

  let usage = previous_usage ^ usage_prefixes
  and arguments = [("--asn-list", String(fun x -> (all := false; asn_filename := x)), "")] in
   
  (* Parse command lines arguments *)
  let args_length = Array.length args_array in
  match args_length with
    | 0 | 1-> (Printf.printf "%s" usage; exit 1)
    | _ -> ();

  begin
    try
      Arg.parse_argv args_array arguments
                     (fun x -> match String.length !filename with 0 -> filename := x |  _ -> ())
                     usage
    with
    | Arg.Bad(_) -> (Printf.printf "%s" usage; exit 1)
    | _ -> ()
  end;

  let asn_list = match String.length !asn_filename with
                 | 0 -> []
                 | _ -> asn_from_file !asn_filename in

  let _ = match Sys.file_exists !filename with
                 | false -> (Printf.printf "%s" usage; exit 1)
                 | true -> () in

  (* Check the file's extension and create the parsing module. *)
  let m = choose_module !filename in
  let module Mrt = MrtParser ((val m : InputRaw)) in

  (** Parse the dump and outputs prefixes corresponding to the asn_list. *)
  let inc = Mrt.Input.create !filename in
  try
    while true
    do
      let hdr = Mrt.mrt_hdr inc in
      match hdr with
      | MRTHeader(ts, TABLE_DUMP(afi, vn, sn, prefix, td_ts, pi, pa, l)) -> 
                         (match find_asn_attr l asn_list !all with
                         | Some(asn, as_list) -> let asn_str = Printf.sprintf "%lu " asn in
                                                 print_prefixes ~spacing:asn_str [prefix]
                         | None -> ())

      | MRTHeader(ts, BGP4MP(MESSAGE(_, _, _, IPv4(pi), IPv4(li), BGP_UPDATE(wr, l, prefixes))))
      | MRTHeader(ts, BGP4MP(MESSAGE(_, _, _, IPv6(pi), IPv6(li), BGP_UPDATE(wr, l, prefixes)))) ->
                         (match find_asn_attr l asn_list !all with
                         | Some(asn, as_list) -> let asn_str = Printf.sprintf "%lu " asn in
                                                 print_prefixes ~spacing:asn_str prefixes;
                                                 print_prefixes ~spacing:asn_str wr
                         | None -> ())

      | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV4_UNICAST(seq, Prefix(IPv4(prefix), plen_bits), l)))
      | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV6_UNICAST(seq, Prefix(IPv6(prefix), plen_bits), l))) ->
                         (match find_asn_re l asn_list !all with
                         | Some(asn, as_list) -> Printf.printf "%lu %s/%i\n" asn prefix plen_bits
                         | None -> ())


      | _ -> ();
      flush stdout
    done
  with
  | End_of_file -> ()
