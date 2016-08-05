(* MaBo - MRT & BGP OCaml types
 * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
 *
 * This module defines MRT & BGP OCaml types parsed by MaBo. The names should
 * be self explanatory.
 *
 * Notes:
 *   - The MRT format is described in RFC6396 
 *   - BGP messages are described in RFC4271
 *   - BGP attributes are listed in
 *       http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xml
 *   - OPEN messages capabilities are listed in
 *       https://www.iana.org/assignments/capability-codes/capability-codes.xml
 *)       


exception MRTParsingError of string
exception MRTPrintingError of string
exception SubError of string


type ip_address = IPv4 of string 
                | IPv6 of string
		| UnknownIP of int


type prefix = Prefix of ip_address * int


type asn = ASN16 of int32
         | ASN32 of int32


type peer_entry = PeerEntry of string * ip_address * asn
                | UnknownPeerEntry of int


type path_segment = AS_SET of asn list
                  | AS_SEQUENCE of asn list
                  | AS_CONFED_SET of asn list
                  | AS_CONFED_SEQUENCE of asn list
		  | Unknown_AS_PATH_TYPE of int


type afi_type = INET
              | INET6
	      | UnknownAFI of int


type safi_type = UNICAST_FORWARDING
               | MULTICAST_FORWARDING
	       | UnknownSAFIType of int


(** Note: the declaration order is the sort order. *)
type bgp_attributes = BGPAttributeORIGIN of int * int                                          (*  1 *)
                    | BGPAttributeAS_PATH of int * path_segment list                           (*  2 *)
                    | BGPAttributeAS4_PATH of int * path_segment list                          (* 17 *)
                    | BGPAttributeNEXT_HOP of int * string                                     (*  3 *)
                    | BGPAttributeMULTI_EXIT_DISC of int * int32                               (*  4 *)
		    | BGPAttributeATOMIC_AGGREGATE of int                                      (*  6 *)
                    | BGPAttributeAGGREGATOR of int * asn * string                             (*  7 *)
                    | BGPAttributeMP_REACH_NLRI of int * afi_type * safi_type * ip_address list * prefix list (* 14 *)
                    | BGPAttributeMP_REACH_NLRI_abbreviated of int * ip_address list           (* 14 *)
                    | BGPAttributeMP_UNREACH_NLRI of int * afi_type * safi_type * prefix list  (* 15 *)
                    | BGPAttributeAS4_AGGREGATOR of int * asn * string                         (* 18 *)
                    | BGPAttributeUnknown of int * int
                    | BGPAttributeCOMMUNITY of int * (int * int) list                          (*  8 *)


type rib_entry = RIBEntry of int * int32 * int * bgp_attributes list


type table_dump_v2 = PEER_INDEX_TABLE of string * string * peer_entry list   (* 13 1 *)
	           | RIB_IPV4_UNICAST of int32 * prefix * rib_entry list     (* 13 2 *)
	           | RIB_IPV6_UNICAST of int32 * prefix * rib_entry list     (* 13 4 *)


type capabilities = Multiprotocol of afi_type * safi_type (*   1 *)
                  | RouteREFRESH                          (*   2 *)
		  | FourBytesASN of asn                   (*  65 *)
		  | RouteREFRESH_CISCO                    (* 128 *)
		  | MULTISESSION_CISCO of int		  (* 131 *)
		  | UnknownCapability of int * int


type open_parameters = Reserved                          (* 0 *)
                     | Authentication                    (* 1 *)
                     | Capabilities of capabilities list (* 2 *)
		     | UnknownParameter of int


type bgp_messages = BGP_OPEN of int * asn * int * string * open_parameters list   (* 1 *)
                  | BGP_UPDATE of prefix list * bgp_attributes list * prefix list (* 2 *)
                  | BGP_NOTIFICATION of int * int * string                        (* 3 *)
                  | BGP_KEEPALIVE                                                 (* 4 *)
                  | BGP_UNKNOWN of int


type fsm_state = Idle        (* 1 *)
               | Connect     (* 2 *)
	       | Active      (* 3 *)
	       | OpenSent    (* 4 *)
	       | OpenConfirm (* 5 *)
	       | Established (* 6 *)
	       | FSM_STATE_UNKNOWN of int


type bgp4mp = STATE_CHANGE of asn * asn * int * afi_type * ip_address * ip_address * fsm_state * fsm_state  (* 16 0 *)
            | MESSAGE     of asn * asn * int * ip_address * ip_address * bgp_messages (* 16 1 *)
	    | MESSAGE_AS4 of asn * asn * int * ip_address * ip_address * bgp_messages (* 16 4 *)
	    | STATE_CHANGE_AS4 of asn * asn * int * afi_type * ip_address * ip_address * fsm_state * fsm_state  (* 16 5 *)


type mrt_types = TABLE_DUMP of afi_type * int * int * prefix * int32 * ip_address * int32 * bgp_attributes list (* 12 *) 
               | TABLE_DUMP_v2 of table_dump_v2 (* 13 *)
	       | BGP4MP of bgp4mp (* 16 *)
               | Unknown of int * int * string


type mrt = MRTHeader of int32 * mrt_types
