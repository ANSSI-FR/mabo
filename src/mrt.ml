(* MaBo - MRT & BGP parser
 * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
 *
 * This module implements MRTParser that parses MRT messages. The entry point is
 * the mrt_hdr function.
 *
 * Notes:
 *   - BGP OPEN message capabilities are described here:
 *       https://www.juniper.net/techpubs/en_US/junose10.0/information-products/topic-collections/swconfig-bgp-mpls/capability-negotiation.html
 *
 *)


open Types
open MrtTools
open Inputs
open Printers


(** MrtParser - a functor that abstract MRT parsing *)
module MrtParser = functor (R : InputRaw) -> struct

  module Input = MkInput (R);;

  (** Create the input *)
  let init s = Input.create s

  
  (** Parse MRT 'Peer entries' *)
  let parse_peers pc l =
    let rec internal p l= 
      match l with
      |0 -> []
      |_ -> (let typ = Input.get_byte p in
	    let bgpid = Input.get_ip4 p in
	    match typ with
	    | 0 -> let ipv4 = Input.get_ip4 p in
		   let asn16 = Input.get_short p in
		     PeerEntry(bgpid, IPv4(ipv4), ASN16(Int32.of_int asn16))::(internal p (l-1))

	    | 1 -> let ipv6 = Input.get_ip6 p in
		   let asn16 = Input.get_short p in
		     PeerEntry(bgpid, IPv6(ipv6), ASN16(Int32.of_int asn16))::(internal p (l-1))

	    | 2 -> let ipv4 = Input.get_ip4 p in
		   let asn32 = Input.get_int32 p in
		     PeerEntry(bgpid, IPv4(ipv4), ASN32(asn32))::(internal p (l-1))

	    | 3 -> let ipv6 = Input.get_ip6 p in
		   let asn32 = Input.get_int32 p in
		     PeerEntry(bgpid, IPv6(ipv6), ASN32(asn32))::(internal p (l-1))

	    | t -> UnknownPeerEntry(t)::[])
    in
      internal pc l


  (** Parse the whole MRT peer index table *)
  let parse_peer_index_table pc =
    let bgpid = Input.get_ip4 pc in
    let view_name_length = Input.get_short pc in
    let view_name = match view_name_length with
                    | 0 -> "OPT_view"
                    | l -> Input.get_string pc l in
    let peer_count = Input.get_short pc in
      PEER_INDEX_TABLE(bgpid, view_name, parse_peers pc peer_count)


  (** Parse a list of ASN (16 or 32 bits) *)
  let get_path_segment asn_len pc =
    let path_segment_length = Input.get_byte pc in
    match asn_len with
    | 4 -> let lst = Input.get_list_of_int32 pc path_segment_length in
	   (List.map (fun x -> ASN32(x)) lst)
    | 2 -> let lst = Input.get_list_of_short pc path_segment_length in
	   (List.map (fun x -> ASN16(Int32.of_int x)) lst)
    | n -> raise (MRTParsingError (Printf.sprintf "get_path_segment: unknown AS length: %i" n))


  (** Parse the content of the AS_PATH BGP attribute *)
  let rec parse_attr_as_path asn_len pc =
    try
      let path_segment_type = Input.get_byte pc in
      match path_segment_type with
      | 1 -> let path_segment = get_path_segment asn_len pc in
	 AS_SET(path_segment)::(parse_attr_as_path asn_len pc)

      | 2 -> let path_segment = get_path_segment asn_len pc in
	 AS_SEQUENCE(path_segment)::(parse_attr_as_path asn_len pc)
      | 3 -> let path_segment = get_path_segment asn_len pc in
	 AS_CONFED_SET(path_segment)::(parse_attr_as_path asn_len pc)

      | 4 -> let path_segment = get_path_segment asn_len pc in
	 AS_CONFED_SEQUENCE(path_segment)::(parse_attr_as_path asn_len pc)
      | n -> Unknown_AS_PATH_TYPE(n)::[]
    with
    | Input.ReshapeError(_) -> []


  (** Parse the content of the COMMUNITY BGP attribute *)
  let rec parse_communities pc =
    try
      let asn = Input.get_short pc in (* Why is it a 16 bits ASN ? *)
      let value = Input.get_short pc in
      (asn,value)::(parse_communities pc)
    with
    | Input.ReshapeError(_) -> []


  (** Parse the content of the MP_REACH_NLRI BGP attribute *)
  let parse_reach_nlri_attr attr_flags afi pc =
    let gip,stoi,ip_len,afi_type = match afi with
		     | 1 -> (Input.get_ip4,string_to_ip,4,INET)
		     | 2 -> (Input.get_ip6,string_to_ip6,16,INET6)
		     | n -> raise (MRTParsingError (Printf.sprintf "REACH_NLRI unknown AFI: %i" n)) in
    let safi = Input.get_byte pc in
    let safi_type = match safi with
                    (* 1: UNICAST forwarding 2: MULTICAST forwarding *)
                    | 1 -> UNICAST_FORWARDING
                    | 2 -> MULTICAST_FORWARDING
                    | _ -> UnknownSAFIType(safi) in
    let next_hop_len = Input.get_byte pc in
    let ip_list = Input.get_list_of_ip pc gip ip_len (next_hop_len/ip_len) in
    let reserved = Input.get_byte pc in
    match reserved with
    | 0 -> BGPAttributeMP_REACH_NLRI(attr_flags, afi_type, safi_type,
	 		      List.map (fun x -> match afi with 1 -> IPv4(x) |2 -> IPv6(x) | n -> UnknownIP(n)) ip_list,
			      Input.nlri_get_prefixes pc afi stoi ip_len)
    | _ -> raise (MRTParsingError ("reserved != 0"))


  (** Parse the content of the abbreviated MP_REACH_NLRI BGP attribute *)
  let parse_reach_nlri_attr_abbreviated attr_flags pc =
    let gip,ip_len = Input.get_ip6,16 in
    let next_hop_len = Input.get_byte pc in
    let ip_list = Input.get_list_of_ip pc gip ip_len (next_hop_len/ip_len) in
      BGPAttributeMP_REACH_NLRI_abbreviated(attr_flags, List.map (fun x -> IPv6(x)) ip_list)


  (** Parse the content of the MP_UNRREACH_NLRI BGP attribute *)
  let parse_unreach_nlri_attr attr_flags afi pc = 
    let gip,stoi,ip_len,afi_type = match afi with
		     | 1 -> (Input.get_ip4,string_to_ip,4,INET)
		     | 2 -> (Input.get_ip6,string_to_ip6,16,INET6)
		     | n -> raise (MRTParsingError (Printf.sprintf "UNREACH_NLRI unknown AFI: %i" n)) in
    let safi = Input.get_byte pc in (* 1: UNICAST forwarding 2: MULTICAST forwarding *)
    let safi_type = match safi with 1 -> UNICAST_FORWARDING | 2 -> MULTICAST_FORWARDING | _ -> UnknownSAFIType(safi)
    in
      BGPAttributeMP_UNREACH_NLRI(attr_flags, afi_type, safi_type,
				Input.nlri_get_prefixes pc afi stoi ip_len)

  (** Parse BGP attributes *)
  let rec parse_bgp_attributes ?(asn_len=4) pc get_ip = 
    let internal pc =
      let attr_flags = Input.get_byte pc in
      let attr_type = Input.get_byte pc in 
      let extended_length = (attr_flags land 0b00010000) == 16  in
      let attr_len = match extended_length with
                     | false -> Input.get_byte pc
                     | true -> Input.get_short pc in
      Input.reshape_enter pc attr_len;
      let bgp_attribute = match attr_type with 
      | 1 -> let origin = Input.get_byte pc in
	     BGPAttributeORIGIN(attr_flags, origin)

      | 2 -> let path_segments = parse_attr_as_path asn_len pc in (* XXX: 2 bytes ASN ?!? *)
	     BGPAttributeAS_PATH(attr_flags, path_segments)

      | 3 -> let next_hop = Input.get_ip4 pc in
	     BGPAttributeNEXT_HOP(attr_flags, next_hop)

      | 4 -> let med = Input.get_int32 pc in
	     BGPAttributeMULTI_EXIT_DISC(attr_flags, med)

      | 6 -> BGPAttributeATOMIC_AGGREGATE(attr_flags)

      | 7 -> let asn = match asn_len with
		       | 4 -> ASN32(Input.get_int32 pc)
		       | 2 -> ASN16(Int32.of_int (Input.get_short pc))
		       | n -> raise (MRTParsingError (Printf.sprintf "parse_bgp_attribues: unknown AS length: %i" n))
	     in
	     let ip = Input.get_ip4 pc in
	     BGPAttributeAGGREGATOR(attr_flags, asn, ip)

      | 8 -> BGPAttributeCOMMUNITY(attr_flags, parse_communities pc)

      | 14 -> let afi = Input.get_short ~peak_only:true pc in (* RFC 4760 defines this BGP attribute *)
	      let reach_nlri = match afi with
			     | n when n <= 2 -> let _ = Input.get_short pc in
                                                parse_reach_nlri_attr attr_flags n pc
                             | _             -> parse_reach_nlri_attr_abbreviated attr_flags pc
	      in
		reach_nlri

      | 15 -> let afi = Input.get_short pc in (* RFC 4760 defines this BGP attribute *)
	      let unreach_nlri = parse_unreach_nlri_attr attr_flags afi pc
	      in
		unreach_nlri

      | 17 -> let path_segments = parse_attr_as_path 4 pc in
	      BGPAttributeAS4_PATH(attr_flags, path_segments)

      | 18 -> let asn =Input.get_int32 pc in
	      let ip = Input.get_ip4 pc in
	      BGPAttributeAS4_AGGREGATOR(attr_flags, ASN32(asn), ip)

      | _ -> let _ = Input.get_string pc attr_len in
	     BGPAttributeUnknown(attr_flags, attr_type)
      in
	Input.reshape_exit pc;
	bgp_attribute::(parse_bgp_attributes ~asn_len:asn_len pc get_ip)

    in
     try
       internal pc
     with
     | Input.ReshapeError(_) -> []


  (** Parse MRT TABLE_DUMP *)
  let parse_table_dump pc subtyp =

    (* Ease IP addresses manipulation *)
    let get_ip,stoi,afi = match subtyp with
      | 1 -> Input.get_ip4, (fun x -> IPv4(x)),INET
      | 2 -> Input.get_ip6, (fun x -> IPv6(x)),INET6
      | n -> begin
             let message = Printf.sprintf "TABLE_DUMP unknown address type: %i" n in
             raise (MRTParsingError message)
             end in

    (* Parse the header *)
    let view_number = Input.get_short pc in
    let sequence_number = Input.get_short pc in
    let prefix = stoi (get_ip pc) in
    let plen = Input.get_byte pc in
    let status = Input.get_byte pc in
    let timestamp = Input.get_int32 pc in
    let peer_ip = stoi (get_ip pc) in
    let peer_as = Int32.of_int (Input.get_short pc) in
    let attr_len = Input.get_short pc in

    (* Ensure that status is equal to 1 *)
    let _ = match status with
	    | 1 -> ()
	    | _ -> raise (MRTParsingError "TABLE_DUMP status is not equal to one !") in
    
    (* Parse BGP attributes *)
    Input.reshape_enter pc attr_len;
    let attributes = parse_bgp_attributes ~asn_len:2 pc get_ip in
    Input.reshape_exit pc;

    TABLE_DUMP(afi, view_number, sequence_number, Prefix(prefix, plen), timestamp,
               peer_ip, peer_as, attributes)


  (** Parse MRT 'RIB Entries' *)
  let rec parse_rib_entries pc count get_ip =
    let peer_index = Input.get_short pc in 
    let timestamp = Input.get_int32 pc in
    let attr_len = Input.get_short pc in
    Input.reshape_enter pc attr_len;
    let ribentry = RIBEntry(peer_index, timestamp, attr_len,
                            parse_bgp_attributes pc get_ip) in
    Input.reshape_exit pc;
    match count with
    | 1 -> ribentry::[]
    | _ -> ribentry::(parse_rib_entries pc (count-1) get_ip)


  (** Parse MRT IPv4 'RIB subtypes' *)
  let parse_rib_ipv4_unicast pc get_ip =
    let seq = Input.get_int32 pc in
    let prefix,plen_bits = Input.get_nlri pc string_to_ip 4 in 
    let entry_count = Input.get_short pc in
      RIB_IPV4_UNICAST(seq, Prefix(IPv4(prefix), plen_bits),
                       parse_rib_entries pc entry_count Input.get_ip4)


  (** Parse MRT IPv6 'RIB subtypes' *)
  let parse_rib_ipv6_unicast pc get_ip = 
    let seq = Input.get_int32 pc in
    let prefix,plen_bits = Input.get_nlri pc string_to_ip6 16 in 
    let entry_count = Input.get_short pc in
      RIB_IPV6_UNICAST(seq, Prefix(IPv6(prefix), plen_bits),
                       parse_rib_entries pc entry_count Input.get_ip6)


  (** Parse BGP OPEN message capabilities *)
  let rec parse_open_capabilities pc =
    let internal pc =
      let cap_code = Input.get_byte pc in
      let cap_len = Input.get_byte pc in
      Input.reshape_enter pc cap_len;
      let cap = match cap_code,cap_len with
		| 1  ,_ -> let afi = Input.get_short pc in
			   let safi = Input.get_short pc in
			   let afi_type = match afi with
			                  | 1 -> INET
					  | 2 -> INET6
		                          | n -> UnknownAFI(n) in 
                           let safi_type = match safi with
                                           | 1 -> UNICAST_FORWARDING
                                           | 2 -> MULTICAST_FORWARDING
                                           | _ -> UnknownSAFIType(safi) in
			   Multiprotocol(afi_type, safi_type)
		| 2  ,0 -> RouteREFRESH
		| 65 ,_ -> FourBytesASN(ASN32(Input.get_int32 pc))
		| 128,0 -> RouteREFRESH_CISCO
		| 131,1 -> let value = Input.get_byte pc in
		           MULTISESSION_CISCO(value)
		| _,_ -> let _ = Input.get_string pc cap_len in
		         UnknownCapability(cap_code, cap_len)
      in
        Input.reshape_exit pc;
        cap::(parse_open_capabilities pc)
    in
     try
       internal pc
     with
     | Input.ReshapeError(_) -> []

  

  (** Parse BGP OPEN message parameters *)
  let rec parse_open_parameters pc =
    let internal pc =
      let ptype = Input.get_byte pc in
      let plength = Input.get_byte pc in
      Input.reshape_enter pc plength;
      let param = match ptype with
                  | 2 -> Capabilities(parse_open_capabilities pc)
                  | _ -> let _ = Input.get_string pc plength in
                         UnknownParameter(ptype)
      in
	Input.reshape_exit pc;
	param::(parse_open_parameters pc)
    in
     try
       internal pc
     with
     | Input.ReshapeError(_) -> []


  (** Parse a BGP OPEN message *)
  let parse_bgp_open pc = 
    let version = Input.get_byte pc in
      begin
      match version with
      | 4 -> ()
      | _ -> raise (MRTParsingError "OPEN: version is different than 4 !")
      end;
    let myasn = ASN16(Int32.of_int (Input.get_short pc)) in 
    let hold_time = Input.get_short pc in
    let bgpid = Input.get_ip4 pc in
    let parameters_len = Input.get_byte pc in
    Input.reshape_enter pc parameters_len;
    let parameters = parse_open_parameters pc in
      Input.reshape_exit pc;
      BGP_OPEN(version, myasn, hold_time, bgpid, parameters)


  (** Parse a BGP UPDATE message *)
  let parse_bgp_update pc message_len asn_len =
    let wr_len = Input.get_short pc in (* wr == Withdraw Routes *)
    let wr = match wr_len with
             | 0 -> []
             | n -> Input.get_prefixes_list pc string_to_ip 4 wr_len in
    let wr_prefixes = List.map (fun (i,p) -> Prefix(IPv4(i), p)) wr in
    let attr_len = Input.get_short pc in
    Input.reshape_enter pc attr_len;
    let attr = parse_bgp_attributes ~asn_len:asn_len pc Input.get_ip4 in
    Input.reshape_exit pc;
    (* RFC4271: NLRI length: UPDATE message Length - 23 - Total Path Attributes Length - Withdrawn Routes Length *)
    let nlri_len = message_len - 23 - attr_len - wr_len in
    let nlri = match nlri_len with
               | 0 -> []
               | n -> Input.get_prefixes_list pc string_to_ip 4 nlri_len in
    let nlri_prefixes = List.map (fun (i,p) -> Prefix(IPv4(i), p)) nlri in
      BGP_UPDATE(wr_prefixes, attr, nlri_prefixes)


  (** Parse a BGP NOTIFICATION message *)
  let parse_bgp_notification pc message_size =
    let code = Input.get_byte pc in
    let subcode = Input.get_byte pc in
    let len_data = message_size-21 in
    let data = match len_data with 0 -> "" | n -> Input.get_string pc n in
      BGP_NOTIFICATION(code, subcode, data)


  (** Parse a BGP message encoded after the BGP marker *)
  let parse_bgp_message pc as_size = 
    let marker = Input.get_string pc 16 in
    let _ = match marker with
	    | "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" -> ()
	    | _ -> raise (MRTParsingError "Marker is not valid !") in
    let message_size = Input.get_short pc in
    let message_type = Input.get_byte pc in
    match message_type with
    | 1 -> parse_bgp_open pc
    | 2 -> parse_bgp_update pc message_size as_size
    | 3 -> parse_bgp_notification pc message_size
    | 4 -> BGP_KEEPALIVE
    | n -> let _ = Input.get_string pc (message_size-19) in
           BGP_UNKNOWN(n)
 
        
  (** Parse a MRT BGP4MP message, 16 bits ASN *)
  let parse_bgp4mp_message_as4 pc =
    let peeras = Input.get_int32 pc in
    let localas = Input.get_int32 pc in
    let interface_index = Input.get_short pc in
    let afi = Input.get_short pc in
    let gip,cip,stoi,ip_len = match afi with
	      | 1 -> Input.get_ip4, (fun x -> IPv4(x)), string_to_ip, 4
	      | 2 -> Input.get_ip6, (fun x -> IPv6(x)), string_to_ip6, 16
	      | n -> raise (MRTParsingError (Printf.sprintf "Unknown AFI: %i" n)) in
    let peerip = gip pc in
    let localip = gip pc in
    (* The entire BGP message is included in the BGP Message field. *)
    let bgp_message = parse_bgp_message pc 4
    in
      MESSAGE_AS4(ASN32(peeras), ASN32(localas), interface_index, cip peerip,
                  cip localip, bgp_message)


  (** Parse a MRT BGP4MP message, 32 bits ASN *)
  let parse_bgp4mp_message pc =
    let peeras = Input.get_short pc in
    let localas = Input.get_short pc in
    let interface_index = Input.get_short pc in
    let afi = Input.get_short pc in
    let gip,cip,stoi,ip_len = match afi with
	      | 1 -> Input.get_ip4, (fun x -> IPv4(x)), string_to_ip, 4
	      | 2 -> Input.get_ip6, (fun x -> IPv6(x)), string_to_ip6, 16
	      | n -> raise (MRTParsingError (Printf.sprintf "Unknown AFI: %i" n)) in
    let peerip = gip pc in
    let localip = gip pc in
    (* The entire BGP message is included in the BGP Message field. *)
    let bgp_message = parse_bgp_message pc 2
    in
      MESSAGE(ASN16(Int32.of_int peeras), ASN16(Int32.of_int localas),
              interface_index, cip peerip, cip localip, bgp_message)


  (** Return the BGP FSM OCaml type from an integer *)
  let fsm_state_of_int state =
    match state with
    | 1 -> Idle
    | 2 -> Connect
    | 3 -> Active
    | 4 -> OpenSent
    | 5 -> OpenConfirm
    | 6 -> Established
    | n -> FSM_STATE_UNKNOWN n


  (** Parse a MRT BGP4MP_STATE_CHANGE message, 16 bits ASN *)
  let parse_bgp4mp_state_change pc =
    let peeras = Input.get_short pc in
    let localas = Input.get_short pc in
    let interface_index = Input.get_short pc in
    let afi_num = Input.get_short pc in
    let gip,cip,stoi,ip_len,afi = match afi_num with
	      | 1 -> Input.get_ip4, (fun x -> IPv4(x)), string_to_ip, 4, INET
	      | 2 -> Input.get_ip6, (fun x -> IPv6(x)), string_to_ip6, 16, INET6
	      | n -> raise (MRTParsingError (Printf.sprintf "Unknown AFI: %i" n)) in
    let peerip = gip pc in
    let localip = gip pc in
    let old_state = fsm_state_of_int (Input.get_short pc) in
    let new_state = fsm_state_of_int (Input.get_short pc) in
      STATE_CHANGE(ASN16(Int32.of_int peeras), ASN16(Int32.of_int localas),
                   interface_index, afi, cip peerip, cip localip,
                   old_state, new_state)


  (** Parse a MRT BGP4MP_STATE_CHANGE message, 32 bits ASN *)
  let parse_bgp4mp_state_change_as4 pc =
    let peeras = Input.get_int32 pc in
    let localas = Input.get_int32 pc in
    let interface_index = Input.get_short pc in
    let afi_num = Input.get_short pc in
    let gip,cip,stoi,ip_len,afi = match afi_num with
	      | 1 -> Input.get_ip4, (fun x -> IPv4(x)), string_to_ip, 4, INET
	      | 2 -> Input.get_ip6, (fun x -> IPv6(x)), string_to_ip6, 16, INET6
	      | n -> raise (MRTParsingError (Printf.sprintf "Unknown AFI: %i" n)) in
    let peerip = gip pc in
    let localip = gip pc in
    let old_state = fsm_state_of_int (Input.get_short pc) in
    let new_state = fsm_state_of_int (Input.get_short pc) in
      STATE_CHANGE_AS4(ASN32(peeras), ASN32(localas),
                       interface_index, afi, cip peerip, cip localip,
                       old_state, new_state)


  (** Parse a MRT Common Header *)
  let mrt_hdr pc =
    let timestamp = Input.get_int32 pc
    and typ = Input.get_short pc
    and subtyp = Input.get_short pc 
    and length32 = Input.get_int32 pc
    in
      (* Check if length32 is not longer than 31 bits long. *)
      begin
      match Int32.shift_right_logical length32 31 with
      | 1l -> raise (MRTParsingError(Printf.sprintf "Can't read %lu bytes !" length32))
      | _  -> ()
      end;

      let length = Int32.to_int length32 in
      try
	Input.reshape_enter pc length;
	let tmp = match typ, subtyp with
	| 12,1 -> MRTHeader(timestamp, parse_table_dump pc subtyp)
	| 12,2 -> MRTHeader(timestamp, parse_table_dump pc subtyp)
	| 13,1 -> MRTHeader(timestamp, TABLE_DUMP_v2(parse_peer_index_table pc))
	| 13,2 -> MRTHeader(timestamp, TABLE_DUMP_v2(parse_rib_ipv4_unicast pc Input.get_ip4))
	| 13,4 -> MRTHeader(timestamp, TABLE_DUMP_v2(parse_rib_ipv6_unicast pc Input.get_ip6))
	| 16,0 -> MRTHeader(timestamp, BGP4MP(parse_bgp4mp_state_change pc))
	| 16,1 -> MRTHeader(timestamp, BGP4MP(parse_bgp4mp_message pc))
	| 16,4 -> MRTHeader(timestamp, BGP4MP(parse_bgp4mp_message_as4 pc))
	| 16,5 -> MRTHeader(timestamp, BGP4MP(parse_bgp4mp_state_change_as4 pc))
	| t,s  -> let message = Input.get_string pc length in
		  MRTHeader(timestamp, Unknown(t, s, message))
	in
	  Input.reshape_exit pc;
	  tmp
      with
      | Types.SubError(m) -> (Input.reshape_flush pc;
                              raise (MRTParsingError (Printf.sprintf "MRT dump is broken (SubError: %s)\n" m)))
      | Input.ReshapeError(m) -> (Input.reshape_flush pc;
                                 raise (MRTParsingError (Printf.sprintf "MRT dump is truncated: %li %i/%i %i" timestamp typ subtyp length)))


  (** Look for unsupported AS_PATH type in parsed data *)
  let rec find_unknown_as_path l =
    match l with
    | Unknown_AS_PATH_TYPE(n)::lst -> Printf.printf "Unknown_AS_PATH_TYPE: %i\n" n;
				      find_unknown_as_path lst

    | _::lst -> find_unknown_as_path lst
    | [] -> ()


  (** Look for unsupported BGP attributes in parsed data *)
  let rec find_unknown_attr l = 
    match l with
    | BGPAttributeAS4_PATH(_,l)::lst
    | BGPAttributeAS_PATH(_,l)::lst ->  find_unknown_as_path l;
					find_unknown_attr lst

    | BGPAttributeMP_REACH_NLRI(_, UnknownAFI(a), UnknownSAFIType(s), _, _)::lst -> Printf.printf "UnknownAFI: %i\n" a;
										    Printf.printf "UnknownSAFIType: %i\n" s;
										    find_unknown_attr lst

    | BGPAttributeMP_REACH_NLRI(_, UnknownAFI(a), _, _, _)::lst -> Printf.printf "UnknownAFI: %i\n" a;
								   find_unknown_attr lst

    | BGPAttributeMP_REACH_NLRI(_, _, UnknownSAFIType(n), _, _)::lst -> Printf.printf "UnknownSAFIType: %i\n" n;
									find_unknown_attr lst

    | BGPAttributeUnknown(f,t):: lst -> Printf.printf "BGPAttributeUnknown: %i %i\n" f t;
					find_unknown_attr lst
    | _::lst -> find_unknown_attr lst
    | [] -> ()


  (** Look for unsupported BGP OPEN message capabilities in parsed data *)
  let rec find_unknown_open_cap c =
    match c with
    | Multiprotocol(_, UnknownSAFIType(s))::lst -> Printf.printf "UnknownSAFIType: %i\n" s;
                                                   find_unknown_open_cap lst
    | UnknownCapability(n,s)::lst -> Printf.printf "UnknownCapability: %i %i\n" n s;
                                   find_unknown_open_cap lst
    | _::lst                    -> find_unknown_open_cap lst
    | [] -> ()


  (** Look for unsupported BGP OPEN message parameters in parsed data *)
  let rec find_unknown_open_param p =
    match p with
    | Capabilities(cap)::lst     -> find_unknown_open_cap cap;
                                    find_unknown_open_param lst
    | UnknownParameter(n)::lst -> Printf.printf "UnknownParameter: %i\n" n;
                                  find_unknown_open_param lst
    | _::lst -> find_unknown_open_param lst
    | [] -> ()


  (** Look for unsupported BGP messages in parsed data *)
  let find_unknown_bgp_message l =
    match l with
    | BGP_OPEN(_, _, _, _, parameters) -> find_unknown_open_param parameters
    | BGP_UPDATE(_, attr, _) -> find_unknown_attr attr
    | BGP_NOTIFICATION(_, _, _)
    | BGP_KEEPALIVE -> ()
    | BGP_UNKNOWN(n) ->  Printf.printf "BGP_UNKNOWN: %i\n" n


  (** Print unsupported MRT & BGP types in parsed data *)
  let show_unknown hdr = 
    match hdr with
  | MRTHeader(_, TABLE_DUMP(_, _, _, _, _, _, _, attr)) -> 
      find_unknown_attr attr

    | MRTHeader(_, TABLE_DUMP_v2(PEER_INDEX_TABLE(_,_, l))) -> 
	    let rec find_unknown l =
	      match l with
	      | UnknownPeerEntry(n)::lst -> Printf.printf "UnknowPeerEntry %i\n" n;
					    find_unknown lst
	      | _::lst -> find_unknown lst 
	      | [] -> ()
	    in
	      find_unknown l
	    
    | MRTHeader(_, TABLE_DUMP_v2(RIB_IPV4_UNICAST (_, _, l)))
    | MRTHeader(_, TABLE_DUMP_v2(RIB_IPV6_UNICAST (_, _, l))) ->
	    
	    let rec find_unknown l = 
	      match l with
	      | RIBEntry(_,_,_, rel):: lst -> find_unknown_attr rel;
					      find_unknown lst
	      | [] -> ()
	    in
	      find_unknown l
    
    | MRTHeader(_, BGP4MP(MESSAGE(_, _, _, _, _, bm))) 
    | MRTHeader(_, BGP4MP(MESSAGE_AS4(_, _, _, _, _, bm))) -> find_unknown_bgp_message bm

    | MRTHeader(ts, BGP4MP(STATE_CHANGE(_, _, _, _, _, _, s1, s2)))
    | MRTHeader(ts, BGP4MP(STATE_CHANGE_AS4(_, _, _, _, _, _, s1, s2))) ->
	    let rec find_unknown s1 s2 =
	      match s1,s2 with
	      | FSM_STATE_UNKNOWN n1, FSM_STATE_UNKNOWN n2 -> Printf.printf "Unkown FSM states: %i & %i \n" n1 n2
	      | FSM_STATE_UNKNOWN n, _ 
	      | _, FSM_STATE_UNKNOWN n -> Printf.printf "Unkown FSM state: %i\n" n
	      | _,_ -> ()
	    in
	      find_unknown s1 s2

    | MRTHeader(_, Unknown(t, s, _)) -> Printf.printf "Unknown MRT type %i %i\n" t s

end;;
