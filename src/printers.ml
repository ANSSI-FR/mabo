(* MaBo - MRT & BGP pretty printers
 * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
 *)


open Types
open MrtTools


(** Split a string into a string list using the character c as the delimiter. *)
let rec split s c = 
  try
    let w = String.index s c in
    (safe_sub s 0 w)::(split ((safe_sub s (w+1) ((String.length s) -w-1))) c)
  with
  |Not_found -> [s]


(** Concatenate a list of strings with a delimiter. *)
let rec join s l =
  match l with
  | [] -> ""
  | e::[] -> e
  | e::tail -> e ^ s ^ (join s tail)


(** Return the first u elements of a list. *)
let rec list_until ?(i=0) l u =
  match l with
  | e::lst when i < u -> e::(list_until lst (u-1))
  | _ -> []


(** Return the last u elements of a list. *)
let rec list_from ?(i=0) l u =
  match l with
  | e::lst when i >= u -> e::(list_from lst (u-1))
  | e::lst -> (list_from lst (u-1))
  | _ -> []


(** Convert an integer timestamp to a string formated as MM/DD/YY HH:MM *)
let timestamp_to_string timestamp =
  let ts = Unix.gmtime (Int32.to_float timestamp) in
  Printf.sprintf "%.2i/%.2i/%.2i %.2i:%.2i:%.2i" (ts.Unix.tm_mon+1) ts.Unix.tm_mday (ts.Unix.tm_year-100) ts.Unix.tm_hour ts.Unix.tm_min ts.Unix.tm_sec


(** Print an AS path *)
let print_as_path ?(ap_str="ASPATH:") l =
  let rec pap l =
    let rec p l =
      match l with
      | ASN16(e)::lst
      | ASN32(e)::lst -> (Printf.sprintf "%lu" e)::(p lst)
      | [] -> []
    in
    match l with
    | AS_SET(e)::lst               -> " {" ^ (join "," (p e)) ^ "}" ^ (pap lst)
    | AS_SEQUENCE(e)::lst          -> " " ^ (join " " (p e)) ^ (pap lst)
    | AS_CONFED_SET(e)::lst        -> " [" ^ (join " " (p e)) ^ "]" ^ (pap lst)
    | AS_CONFED_SEQUENCE(e)::lst   -> " (" ^ (join " " (p e)) ^ ")" ^ (pap lst)
    | Unknown_AS_PATH_TYPE(n)::lst -> " " ^ "Unknown PATH type:" ^ (string_of_int n) ^ (pap lst)
    | [] -> ""
  in
    match l with
    | [] -> Printf.printf "%s\n" ap_str
    | _  -> Printf.printf "%s%s\n" ap_str (pap l)


(** Print the COMMUNITY attribute *)
let print_communities l =
  let rec pc l =
    match l with
    | (65535,65281)::lst -> " " ^ "no-export" ^ (pc lst)
    | (asn, value)::lst -> " " ^ (Printf.sprintf "%i:%i" asn value) ^ (pc lst)
    | [] -> ""
  in
    Printf.printf "COMMUNITY:%s\n" (pc l)


(** Print the NLRI attribute *)
let print_nlri l s =
  let rec print_nh l =
    match l with
    | IPv4(ip)::lst
    | IPv6(ip)::lst	-> Printf.printf "NEXT_HOP: %s\n" ip;
	                   print_nh lst
    | UnknownIP(n)::lst -> print_nh lst
    | [] -> ()
  in
    Printf.printf "MP_REACH_NLRI%s\n" s;
    print_nh l


(** Print a list of prefixes *)
let rec print_prefixes ?(spacing="") p =
  match p with
  | Prefix(IPv4(ip), plen)::lst
  | Prefix(IPv6(ip), plen)::lst -> Printf.printf "%s%s/%i\n" spacing ip plen;
                                   print_prefixes ~spacing:spacing lst
  | Prefix(UnknownIP(a), plen)::lst   -> Printf.printf "%sUNKNOWN_IP %i\n" spacing a;
                                         print_prefixes ~spacing:spacing lst
  | [] -> ()


(** Print the FROM line *)
let rec print_from ?(from_str="FROM: ") peers p_i =
  match List.length peers with
  | n when n > p_i -> (let _,ipa,asn = List.nth peers p_i in
                      match ipa with
		      | IPv6(a)
		      | IPv4(a) -> Printf.printf "%s%s AS%lu\n" from_str a asn
		      | UnknownIP(a) -> Printf.printf "%sUNKNOWN_IP %i AS%lu\n" from_str a asn)
  | n -> Printf.printf "%sPEER_NOT_FOUND (%d/%d)\n" from_str p_i n


(** Print a list of RIB entries *)
let print_origin value = 
  let origin_str = match value with
                   | 0 -> "IGP"
                   | 1 -> "EGP"
		   | 2 -> "INCOMPLETE"
		   | _ -> Printf.sprintf "%i (UNKNOWN)" value
  in
    Printf.printf "ORIGIN: %s\n" origin_str


(** Sort the attributes according to their attr_type values. *)
let sort_bgp_attributes attr_lst =
  List.sort compare attr_lst


(** Merge AS_PATH and AS4_PATH.
    The methodology is described in RFC 4893, page 5. *)
let merge_as_path attr_lst = 
  let internal attr_lst ap a4p =
    (* Retrieve AS PATH as a list of integers *)
    let rec get_asn paths =
      let rec p l =
	match l with
	| ASN16(e)::lst
	| ASN32(e)::lst -> e::(p lst)
	| [] -> []
      in
	match paths with
	| AS_SEQUENCE(e)::lst         
	| AS_SET(e)::lst               -> (p e)@(get_asn lst)
	| Unknown_AS_PATH_TYPE(n)::lst -> [-1l]@(get_asn lst)
	| [] -> []
	| AS_CONFED_SEQUENCE(e)::lst
	| AS_CONFED_SET(e)::lst -> let msg = "merge_as_path(): don't know what to do with AS_CONFED_* !\n" in
                                   raise (MRTParsingError msg)
    in
    let get_path attr =
      match List.hd attr with
      | BGPAttributeAS_PATH(_, p)
      | BGPAttributeAS4_PATH(_, p) -> p
      | _ -> []
    in
      (* Compare the number of AS number in AS*_PATH *)
      let lap = get_asn (get_path ap)
      and la4p = get_asn (get_path a4p)
      and lenap = List.length (get_asn (get_path ap))
      and lena4p = List.length (get_asn (get_path a4p)) in
      match lenap < lena4p with
      (* If AS_PATH is smaller than AS4_PATH keep AS_PATH *)
      | true  -> List.filter (fun x -> match x with BGPAttributeAS4_PATH(_, _) -> false | _ -> true) attr_lst
      (* If AS_PATH is greater or equal to AS4_PATH keep merge them *)
      | false -> let new_path = (list_until lap (lenap-lena4p))@la4p in
                 let new_as_set = [AS_SEQUENCE(List.map (fun x -> ASN32(x)) new_path)] in
		 let new_attr_list = List.filter (fun x -> match x with
		                                           | BGPAttributeAS4_PATH(_, _) -> true
							   | _ -> false) attr_lst in
                 (* Return BGPAttributeAS4_PATH only *)
		 List.map (fun x -> match x with
		                    | BGPAttributeAS4_PATH(f, _) -> BGPAttributeAS4_PATH(f, new_as_set)
				    | n -> n) new_attr_list
  in
    (* Isolate AS_PATH and AS4_PATH attributes *)
    let ap = List.filter (fun x -> match x with BGPAttributeAS_PATH(_, _) -> true | _ -> false) attr_lst in
    let a4p = List.filter (fun x -> match x with BGPAttributeAS4_PATH(_, _) -> true | _ -> false) attr_lst in
    (* Decide to keep or merge attributes. *)
    (match List.length ap, List.length a4p with
    | 0,0 -> []
    | 1,0 -> ap
    | 0,1 -> a4p
    | 1,1 -> internal attr_lst ap a4p
    | a,b -> raise (MRTPrintingError (Printf.sprintf "merge_as_path: can't handle these set of AS*_PATH (%i %i) !\n" a b)))


(** Print BGP attributes *)
let rec print_attr l =
  match l with
  | BGPAttributeORIGIN(_, origin)::lst -> print_origin origin;
					  print_attr lst

  | BGPAttributeAS4_PATH(_, path_segments)::lst 
  | BGPAttributeAS_PATH(_, path_segments)::lst -> print_as_path path_segments;
						  print_attr lst

  | BGPAttributeNEXT_HOP(_, next_hop)::lst -> Printf.printf "NEXT_HOP: %s\n" next_hop;
					      print_attr lst

  | BGPAttributeAS4_AGGREGATOR(_, ASN16(asn), ip)::lst (* will never happen *)
  | BGPAttributeAS4_AGGREGATOR(_, ASN32(asn), ip)::lst
  | BGPAttributeAGGREGATOR(_, ASN16(asn), ip)::lst
  | BGPAttributeAGGREGATOR(_, ASN32(asn), ip)::lst -> (match asn with
                                                      | 23456l -> ()
						      |_ -> Printf.printf "AGGREGATOR: AS%lu %s\n" asn ip);
					              print_attr lst

  | BGPAttributeMULTI_EXIT_DISC(_, med)::lst -> Printf.printf "MULTI_EXIT_DISC: %lu\n" med;
						print_attr lst

  | BGPAttributeATOMIC_AGGREGATE(_)::lst -> Printf.printf "ATOMIC_AGGREGATE\n";
					    print_attr lst

  | BGPAttributeCOMMUNITY(_, communities)::lst -> print_communities communities;
                                                  print_attr lst

  | BGPAttributeMP_REACH_NLRI(_, INET, _, nh_list, prefixes)::lst -> print_nlri nh_list "";
		                                                     let rec print_prefixes p =
					                               match p with
					                               | Prefix(IPv4(prefix), plen)::l ->
									   Printf.printf "NLRI: %s/%i\n" prefix plen
					                               | Prefix(_, _)::l -> print_prefixes l
					                               | [] -> ()
								     in
								       print_prefixes prefixes;
								       print_attr lst

  | BGPAttributeMP_REACH_NLRI(_, INET6, _, nh_list, _)::lst -> print_nlri nh_list "(IPv6 Unicast)";
							       print_attr lst

  | BGPAttributeMP_REACH_NLRI(_, _, _, _, _)::lst -> print_attr lst

  | BGPAttributeMP_REACH_NLRI_abbreviated(_, nh_list)::lst -> print_nlri nh_list "(IPv6 Unicast)";
							      print_attr lst

  | BGPAttributeMP_UNREACH_NLRI(_, _, _, _)::lst -> Printf.printf "MP_UNREACH_NLRI(IPv6 Unicast)\n";
                                                    print_attr lst

  | BGPAttributeUnknown(f,t)::lst -> Printf.printf "   UNKNOWN_ATTR(%i, %i)\n" f t;
				     print_attr lst
  | [] -> ()


(** Print RIB entries. *)
let rec print_ribentry ?(peers = []) l = 
  match l with
  | RIBEntry(p_i, ts,_, rel):: lst -> print_from peers p_i;
                                      Printf.printf "ORIGINATED: %s\n" (timestamp_to_string ts);
  				      print_attr (merge_as_path (sort_bgp_attributes rel));
				      print_ribentry lst
  | [] -> ()


(** Print NLRI REACH & UNREACH *)
let rec print_reach_nlri attr =
  let rec get_prefixes p =
    match p with
    | Prefix(IPv6(prefix), plen)::l -> (Printf.sprintf "  %s/%i\n" prefix plen) ^
                                       (get_prefixes l)
    | Prefix(_, _)::l -> get_prefixes l
    | [] -> ""
  in
  let rec internal attr ann_str with_str = 
    match attr with
    | BGPAttributeMP_REACH_NLRI(_, INET6, _, _, prefixes)::lst -> internal lst (ann_str ^ (get_prefixes prefixes)) with_str
    | BGPAttributeMP_UNREACH_NLRI(_, INET6, _, prefixes)::lst -> internal lst ann_str (with_str ^ (get_prefixes prefixes))
    | _::lst -> internal lst ann_str with_str
    | [] -> ann_str,with_str
  in

  let announce, withdraw = internal attr "" "" in

  (match String.length announce with
  | 0 -> ()
  | _ -> Printf.printf "ANNOUNCE\n%s" announce);

  (match String.length withdraw with
  | 0 -> ()
  | _ -> Printf.printf "WITHDRAW\n%s" withdraw)


(** Convert a FSM state to a string *)    
  let fsm_state_to_str state =
    match state with
    | Idle -> "Idle"
    | Connect -> "Connect"
    | Active -> "Active"
    | OpenSent -> "Opensent"
    | OpenConfirm -> "Openconfirm"
    | Established -> "Established"
    | FSM_STATE_UNKNOWN n -> Printf.sprintf "UNKNOWN STATE %i" n


(** Print the MRT header *)
let rec get_peers l = 
  match l with
  | PeerEntry(b, i, ASN16(a))::lst
  | PeerEntry(b, i, ASN32(a))::lst -> (b, i, a)::(get_peers lst)
  | _::lst -> get_peers lst
  | [] -> []


let print_mrt ?(peers = []) hdr = 
  match hdr with
  | MRTHeader(ts, TABLE_DUMP_v2(PEER_INDEX_TABLE(bgpid, viewname, l))) ->
          let rec print l =
	    match l with
	    | PeerEntry(b, IPv4(i), ASN16(a))::lst
	    | PeerEntry(b, IPv6(i), ASN16(a))::lst
	    | PeerEntry(b, IPv4(i), ASN32(a))::lst
	    | PeerEntry(b, IPv6(i), ASN32(a))::lst -> Printf.printf "PEER: %s %s %lu\n" b i a;
	                                              print lst
	    | _::lst -> print lst
	    | [] -> ()
	  in
	    Printf.printf "TIME: %s\n" (timestamp_to_string  ts);
	    print l
	  
  | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV4_UNICAST(seq, Prefix(prefix46, plen_bits), l)))
  | MRTHeader(ts, TABLE_DUMP_v2(RIB_IPV6_UNICAST(seq, Prefix(prefix46, plen_bits), l))) -> 
      let prefix_header = match prefix46 with
      | IPv4(prefix) -> (Printf.sprintf "TYPE: TABLE_DUMP_V2/IPV4_UNICAST\n") ^
		        (Printf.sprintf "PREFIX: %s/%i\n" prefix plen_bits)
      | IPv6(prefix) -> (Printf.sprintf "TYPE: TABLE_DUMP_V2/IPV6_UNICAST\n") ^
		        (Printf.sprintf "PREFIX: %s/%i\n" prefix plen_bits)
      | UnknownIP(a) -> (Printf.sprintf "TYPE: TABLE_DUMP_V2/UNKNOWNIP\n") ^
                        (Printf.sprintf "PREFIX: UNKNOWN_IP %i\n" a)
      in
      let dump_header = (Printf.sprintf "TIME: %s\n" (timestamp_to_string  ts)) ^
			prefix_header ^
		        (Printf.sprintf "SEQUENCE: %lu\n" seq) in

      let rec print_re l dump_hdr =
        match l with
	| re::lst -> Printf.printf "%s" dump_hdr;
		     print_ribentry ~peers:peers [re];
		     print_newline ();
		     print_re lst dump_hdr
	| [] -> ()
      in
        print_re l dump_header

  | MRTHeader(ts, BGP4MP(MESSAGE(ASN16(_), ASN16(_), _, _, _, BGP_OPEN(v, ASN16(myasn), htime, id, params))))
  | MRTHeader(ts, BGP4MP(MESSAGE_AS4(ASN32(_), ASN32(_), _, _, _, BGP_OPEN(v, ASN16(myasn), htime, id, params)))) ->
	             Printf.printf "TIME: %s\n" (timestamp_to_string  ts);
		     Printf.printf "TYPE: BGP4MP/MESSAGE/Open\n";
		     Printf.printf "VERSION: %d\n" v;
		     Printf.printf "AS: %lu\n" myasn;
		     Printf.printf "HOLD_TIME: %d\n" htime;
		     Printf.printf "ID: %s\n" id;
		     Printf.printf "OPT_PARM_LEN: %d\n" (List.length params);
		     print_newline ()

  | MRTHeader(ts, BGP4MP(MESSAGE(ASN16(pa), ASN16(la), ii, IPv4(pi), IPv4(li), BGP_UPDATE(wr, attr, prefixes))))
  | MRTHeader(ts, BGP4MP(MESSAGE(ASN32(pa), ASN32(la), ii, IPv4(pi), IPv4(li), BGP_UPDATE(wr, attr, prefixes))))
  | MRTHeader(ts, BGP4MP(MESSAGE_AS4(ASN32(pa), ASN32(la), ii, IPv4(pi), IPv4(li), BGP_UPDATE(wr, attr, prefixes))))
  | MRTHeader(ts, BGP4MP(MESSAGE(ASN16(pa), ASN16(la), ii, IPv6(pi), IPv6(li), BGP_UPDATE(wr, attr, prefixes))))
  | MRTHeader(ts, BGP4MP(MESSAGE_AS4(ASN32(pa), ASN32(la), ii, IPv6(pi), IPv6(li), BGP_UPDATE(wr, attr, prefixes)))) ->
	             Printf.printf "TIME: %s\n" (timestamp_to_string  ts);
          	     Printf.printf "TYPE: BGP4MP/MESSAGE/Update\n";
		     Printf.printf "FROM: %s AS%lu\n" pi pa;
		     Printf.printf "TO: %s AS%lu\n" li la;
		     print_attr (merge_as_path (sort_bgp_attributes attr));
		     print_reach_nlri attr; (* IPv6 only *)
		     (match List.length wr with
		     | 0 -> ()
		     | n -> Printf.printf "WITHDRAW\n";
		            print_prefixes ~spacing:"  " wr);
		     (match List.length prefixes with
		     | 0 -> ()
		     | n -> Printf.printf "ANNOUNCE\n";
		            print_prefixes ~spacing:"  " prefixes);
		     print_newline ()

  | MRTHeader(ts, BGP4MP(MESSAGE(ASN16(pa), ASN16(la), ii, IPv4(pi), IPv4(li), BGP_KEEPALIVE)))
  | MRTHeader(ts, BGP4MP(MESSAGE_AS4(ASN32(pa), ASN32(la), ii, IPv4(pi), IPv4(li), BGP_KEEPALIVE)))
  | MRTHeader(ts, BGP4MP(MESSAGE(ASN16(pa), ASN16(la), ii, IPv6(pi), IPv6(li), BGP_KEEPALIVE)))
  | MRTHeader(ts, BGP4MP(MESSAGE_AS4(ASN32(pa), ASN32(la), ii, IPv6(pi), IPv6(li), BGP_KEEPALIVE))) ->
	             Printf.printf "TIME: %s\n" (timestamp_to_string  ts);
          	     Printf.printf "TYPE: BGP4MP/MESSAGE/Keepalive\n";
		     Printf.printf "FROM: %s AS%lu\n" pi pa;
		     Printf.printf "TO: %s AS%lu\n" li la;
		     print_newline ()

  | MRTHeader(ts, BGP4MP(MESSAGE(ASN16(pa), ASN16(la), ii, IPv4(pi), IPv4(li), BGP_NOTIFICATION(c, sc, d))))
  | MRTHeader(ts, BGP4MP(MESSAGE_AS4(ASN32(pa), ASN32(la), ii, IPv4(pi), IPv4(li), BGP_NOTIFICATION(c, sc, d))))
  | MRTHeader(ts, BGP4MP(MESSAGE(ASN16(pa), ASN16(la), ii, IPv6(pi), IPv6(li), BGP_NOTIFICATION(c, sc, d))))
  | MRTHeader(ts, BGP4MP(MESSAGE_AS4(ASN32(pa), ASN32(la), ii, IPv6(pi), IPv6(li), BGP_NOTIFICATION(c, sc, d)))) ->
	             Printf.printf "TIME: %s\n" (timestamp_to_string  ts);
          	     Printf.printf "TYPE: BGP4MP/MESSAGE/Notification %i %i %s\n" c sc d;
		     Printf.printf "FROM: %s AS%lu\n" pi pa;
		     Printf.printf "TO: %s AS%lu\n" li la;
		     print_newline ()

  | MRTHeader(ts, BGP4MP(STATE_CHANGE(ASN16(pa), ASN16(la), ii, afi, IPv4(pi), IPv4(li), old_state, new_state)))
  | MRTHeader(ts, BGP4MP(STATE_CHANGE(ASN16(pa), ASN16(la), ii, afi, IPv6(pi), IPv6(li), old_state, new_state)))
  | MRTHeader(ts, BGP4MP(STATE_CHANGE_AS4(ASN32(pa), ASN32(la), ii, afi, IPv4(pi), IPv4(li), old_state, new_state)))
  | MRTHeader(ts, BGP4MP(STATE_CHANGE_AS4(ASN32(pa), ASN32(la), ii, afi, IPv6(pi), IPv6(li), old_state, new_state))) ->
	             Printf.printf "TIME: %s\n" (timestamp_to_string  ts);
          	     Printf.printf "TYPE: BGP4MP/STATE_CHANGE\n";
		     Printf.printf "PEER: %s AS%lu\n" pi pa;
		     Printf.printf "STATE: %s/%s\n" (fsm_state_to_str old_state) (fsm_state_to_str new_state);
		     print_newline ()
  

  | MRTHeader(_, _) -> ()
