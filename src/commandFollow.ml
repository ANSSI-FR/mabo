(* Guillaume Valadon <guillaume.valadon@ssi.gouv.fr> *)


(***
     Follow routes changes giving a prefixes list, a full view and a list of updates.
 ***)


open Mrt
open MrtTools
open Types
open Printers
open Inputs

(** Set module dedicated to IP prefixes. *)
let compare_prefixes pre1 pre2 =
  match pre1,pre2 with
  | Prefix(IPv4(p1), m1), Prefix(IPv6(p2), m2) -> -1
  | Prefix(IPv6(p1), m1), Prefix(IPv4(p2), m2) ->  1
  | Prefix(UnknownIP(_), _), _                 ->  1
  | _, Prefix(UnknownIP(_), _)                 -> -1
  | Prefix(IPv4(p1), m1), Prefix(IPv4(p2), m2)
  | Prefix(IPv6(p1), m1), Prefix(IPv6(p2), m2) -> begin
                                                  match compare p1 p2 with
                                                  | 0 -> compare m1 m2
						  | n -> n
						  end

module PrefixSet = Set.Make (struct type t = prefix let compare = compare_prefixes end)


(** Get a list of IPv4 prefixes from a file. *)
let prefixes_from_file filename =
  let inc = open_in filename
  and set_ref = ref PrefixSet.empty
  and loop = ref true in
  while !loop
  do
    try
      let tmp_prefix = Str.split (Str.regexp_string "/") (input_line inc) in
      let tmp = List.nth tmp_prefix 0 in
      let prefix = match String.contains tmp ':' with
		   | true  -> IPv6(tmp)
		   | false -> IPv4(tmp)
      in
	let elt = Prefix(prefix, int_of_string (List.nth tmp_prefix 1)) in
	set_ref := (PrefixSet.add elt !set_ref)
    with
    | End_of_file -> loop := false
  done;
  !set_ref


(** Prefix list to string. *)
let rec p2s prx = 
  match prx with
  | Prefix(IPv4(p), plen)::lst
  | Prefix(IPv6(p), plen)::lst -> (Printf.sprintf "%s/%i " p plen) ^ (p2s lst)
  | Prefix(UnknownIP(_), plen)::lst -> ""
  | [] -> ""


(** Ease the addition and the removal of prefixes. *)
let rec apply ts f p k_p l =
  match l with
  | tmp::lst -> begin
                let new_k_p = match PrefixSet.mem tmp p with
		| true  -> let t = f tmp k_p in
			   t
		| false -> k_p
		in
		  apply ts f p new_k_p lst
		end

  | [] -> k_p


(** Ease the lookup into the hash table. *)
let lookup_peer ht k =
  try
    Hashtbl.find ht k
  with
  | Not_found -> PrefixSet.empty


(** Get NLRI REACH & UNREACH attributes. *)
let rec get_nlri_reach_unreach attr reach unreach = 
  match attr with
  | BGPAttributeMP_REACH_NLRI(_, _, _, _, pr)::lst -> get_nlri_reach_unreach lst (reach@pr) unreach
  | BGPAttributeMP_UNREACH_NLRI(_, _, _, wr)::lst  -> get_nlri_reach_unreach lst reach (unreach@wr)
  | _::lst -> get_nlri_reach_unreach lst reach unreach
  | [] -> (reach, unreach)


(** Get the list of peers from a RIBEntry list.*)
let _peer2str l i =
  match List.length l with
  | n when n > i -> (let _,ipa,asn = List.nth l i in
		     match ipa with
		     | IPv6(a)
		     | IPv4(a)      -> Printf.sprintf "%s %lu" a asn
		     | UnknownIP(a) -> Printf.sprintf "UNKNOWN_IP %i %lu" a asn)
  | _ -> Printf.sprintf "UNKNOWN_PEER UNKNOWN_ASN"

let rec list_of_peers peers rel = 
  match rel with
  | RIBEntry(peer_index, _, _, _)::lst -> (_peer2str peers peer_index)::(list_of_peers peers lst)
  | [] -> []


(** Count all known prefixes. *)
let count_prefixes ht =
  (* Merge all the PrefixSet from the hash table. *)
  let tmp_set = ref PrefixSet.empty in
  Hashtbl.iter (fun a b -> tmp_set := PrefixSet.union !tmp_set b) ht;
  (* Cound unique prefixes. *)
  PrefixSet.cardinal !tmp_set


(** Define the main function *)
let main previous_usage args_array =

  (* Simple arguments checking. *)
  let usage_follow = " follow prefixes_file.txt mrt_full_view.dump mrt_update.dump ...

Follow a list of IP prefixes in MRT files

Arguments:
  prefixes_file.txt      a text file containing IPv4 and IPv6 prefixes
  mrt_full_view.dump     a MRT full-view dump
  mrt_update.dump ...    a list of MRT BGP UPDATE messages dump\n" in

  let usage = previous_usage ^ usage_follow in
  begin
  match Array.length args_array > 3 with
  | false -> (Printf.eprintf "%s" usage; exit 1)
  | true -> ()
  end;

  (* Load MRT dumps. *)
  let prefixes = prefixes_from_file (Array.get args_array 1)
  and full_view = Array.get args_array 2
  and updates = list_from (Array.to_list args_array) 3 in

  (* Create the parsing module. *)
  let m = choose_module full_view in
  let module Mrt = MrtParser ((val m : InputRaw)) in

  (** Parse dumps. *)
  let parse_dumps filename prefixes known_prefixes = 
    let inc = Mrt.Input.create filename in
    let peers = ref [] in
    let ret_ts = ref Int32.zero in
    begin
    try
      while true
      do
        match Mrt.mrt_hdr inc  with

        (* Get the peers list. *)
        | MRTHeader(ts, TABLE_DUMP_v2(PEER_INDEX_TABLE(bgpid, viewname, l))) -> peers := get_peers l

        (* An IP prefix is announced. *)
        | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV4_UNICAST(_, prefix, ribentries)))
        | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV6_UNICAST(_, prefix, ribentries))) ->
              begin
              (* Store each peer as a different key in the hash table. *)
              let rec _loop l f = 
                match l with
                | e::lst -> let set_old = lookup_peer known_prefixes e in
                            let set_new = apply ts PrefixSet.add prefixes set_old [prefix] in
                            if set_old != set_new
                            then begin 
                              Hashtbl.replace known_prefixes e set_new;
                              _loop lst true
                            end else
                              _loop lst f
                | [] -> f
              in

                let modified = _loop (list_of_peers !peers ribentries) false in
                if modified
                then begin
                  Printf.printf "%lu %i\n" ts (count_prefixes known_prefixes)
               end;

               ret_ts := ts
              end
   
        (* An update is received for an IP prefix. *)
        | MRTHeader(ts, BGP4MP(MESSAGE(pa, _, _, pi, _, BGP_UPDATE(wr, attr, pr))))
        | MRTHeader(ts, BGP4MP(MESSAGE_AS4(pa, _, _, pi, _, BGP_UPDATE(wr, attr, pr)))) ->
              begin
              (* Build the key *)
              let key = _peer2str [(0, pi, match pa with ASN16(asn) | ASN32(asn) -> asn)] 0 in

              (* Remove then add prefixes. *)
              let tmp0 = lookup_peer known_prefixes key in
              let tmp1 = apply ts PrefixSet.remove prefixes tmp0 wr in
              let tmp2 = apply ts PrefixSet.add    prefixes tmp1 pr in

              let reach,unreach = get_nlri_reach_unreach attr [] [] in
              let tmp3 = apply ts PrefixSet.remove prefixes tmp2 unreach in
              let tmp4 = apply ts PrefixSet.add    prefixes tmp3 reach in

              Hashtbl.replace known_prefixes key tmp4;
              if tmp0 != tmp4 
              then begin
                Printf.printf "%lu %i\n" ts (count_prefixes known_prefixes);
                end;

              ret_ts := ts
              end

        | MRTHeader(ts, _) -> ret_ts := ts
      done;
    with
    | End_of_file -> ()
    end;
    Printf.printf "%lu %i\n" !ret_ts (count_prefixes known_prefixes);
    known_prefixes

  in

  (* 1. get prefixes included in the full view. *)
  let known_prefixes = parse_dumps full_view prefixes (Hashtbl.create 20) in

  (* 2. add/remove prefixes according to updates *)
  let rec do_updates updates prefixes known_prefixes =
    match updates with
    | u::l -> let tmp = parse_dumps u prefixes known_prefixes in
              do_updates l prefixes tmp
    | [] -> ()
  in
    do_updates (sort_mrt_dumps updates) prefixes known_prefixes
