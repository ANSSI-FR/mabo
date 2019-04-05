(* MaBo - input source abstraction
 * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
 *
 * This module provides an abstraction over the input source (InputRaw for
 * strings, InputFile for binary files, InputGzip for gzip files, or InputBz2 
 * for bz2 file). They can be manipulated thanks to the functions create
 * (i.e. open for files) or retrieve (i.e. get some bytes).
 *
 * The MkInput functor takes advantage of these abstracted inputs and provides
 * ease access to binary elements through functions such as get_byte, get_short,
 * or get_ip6. Some functions are specifically designed to parse MRT and BGP
 * low-level types such as NLRI.
 *)


open Bytes
open Types
open Printers
open MrtTools


(** Input type definition *)
module type InputRaw = sig
  type t (* the abstract input handle *)
  val create : string -> t (* create the input *)
  val retrieve : t -> int -> string * int (* get some bytes *)
end;;


(** InputString - use a string as the input *)
module InputString = struct
  type t = { mutable content: string; mutable offset: int; max_offset: int }

  let create s = { content = s; offset = 0; max_offset = String.length s }

  let retrieve m len =
    match String.length m.content with
    | 0 -> "", 0
    | _ -> m.content, m.max_offset

end;;


(** InputFile - use a file as the input *)
module InputFile = struct
  type t = Pervasives.in_channel

  let create s = 
    let fd = open_in_bin s in
    Gc.finalise Pervasives.close_in fd;
    fd

  let retrieve fd len =
    let tmp = Bytes.create len in
    match Pervasives.input fd tmp 0 len with
    | 0 -> "",0
    | n -> (safe_sub (Bytes.to_string tmp) 0 n), n (* return the correct number of bytes *)

end;;


(** InputGzip - use a gzip file as the input *)
module InputGzip = struct
  type t = Gzip.in_channel

  let create s = 
    let fd = Gzip.open_in s in
    Gc.finalise Gzip.close_in fd;
    fd

  let retrieve fd len =
    let tmp = Bytes.create len in
    match Gzip.input fd tmp 0 len with
    | 0 -> "",0
    | n -> (safe_sub (Bytes.to_string tmp) 0 n),n (* return the correct number of bytes *)

end;;


(** InputBz2 - use a bz2 file as the input *)
module InputBz2 = struct
  type t = Bz2.in_channel

  let create s = 
    let pervasives_fd = open_in_bin s in
    Gc.finalise Pervasives.close_in pervasives_fd;
    let fd = Bz2.open_in pervasives_fd in
    Gc.finalise Bz2.close_in fd;
    fd

  let retrieve fd len =
    let tmp = Bytes.create len in
    match Bz2.read fd tmp 0 len with
    | 0 -> "",0
    | n -> (safe_sub (Bytes.to_string tmp) 0 n),n (* return the correct number of bytes *)

end;;


(** MkInput - a functor that abstract the manipulation of inputs
 *
 * Shapes are used to ensure that enough bytes are always available to getters.
 * They are implemented using the functions check, reshape_enter, reshape_exit.
 * As a consequence, a TLV encoded value, V, such as a BGP attribute won't be
 * able to access more than V bytes.
 *)
module MkInput = functor (R : InputRaw) -> struct 

  (* The internal type that stores shapes and data. *)
  type t = { mutable data: string; mutable offset: int; 
             mutable max_offset: int option; fd : R.t;
	     mutable shapes: int option list }

  exception ReshapeError of string

  (* Map the abstracted input to the internal type *)
  let create s =
    let tmp = R.create s in
    { data = ""; offset = 0; max_offset = None; fd = tmp; shapes = [] } 

  (* Retrieve until the correct amount of bytes is obtained. *)
  let rec smart_retrieve m len_needed =
    match R.retrieve m.fd len_needed with
    | "",0 -> "",0
    | data,n when n < len_needed ->
        begin
          let tmp_got,tmp_n = smart_retrieve m (len_needed-n) in
          data^tmp_got,n+tmp_n
        end
    | data,n -> data,n

  (* Check if the current 'shape' contains enough data *)
  let check m len =
    (match m.max_offset = None || Some(m.offset + len) <= m.max_offset with
    | true -> ()
    | false ->
        let get_max x = match x with None -> 999999 | Some(n) -> n in
        let max_r = (get_max m.max_offset) in
        let err_msg = Printf.sprintf "Too far ! %i > %i" (m.offset+len) max_r in 
        raise (ReshapeError err_msg));

    (* Retrieve at least 'len' bytes *)
    let data_len = (String.length m.data) - m.offset in
    match data_len >= len with
    | true  -> () (* there is enough bytes *)
    | false ->
        (* get some more bytes *)
        let tmp,tmp_len = smart_retrieve m (len-data_len) in
        match tmp_len with
        | 0 ->
            raise End_of_file
        | n when n < (len-data_len) ->
            raise End_of_file
        | _ ->
            m.data <- tmp;
            m.offset <- 0

  (* Reshape enter, i.e. create a new shape *)
  let reshape_enter m l =
    check m l;
    m.shapes <- m.max_offset::m.shapes;
    m.max_offset <- Some(m.offset+l)

  (* Reshape exit, i.e. remove the current shape *)
  let reshape_exit m =
    match List.length m.shapes with
    | 0 -> raise (ReshapeError "Can't reshape_exit() !")
    | _ -> begin
           m.max_offset <- List.nth m.shapes 0;
	   m.shapes <- list_from m.shapes 1;
	   end

  let get_string m len =
    check m len;
    let tmp = safe_sub m.data m.offset len in
    m.offset <- m.offset + len;
    tmp

  (* Reshape flush, i.e. forget about shapes. Used in attempts to parse broken
   * dumps *)
  let reshape_flush m =
    match List.length m.shapes with
    | 0 -> raise (ReshapeError "Can't reshape_flush() !")
    | _ -> begin
	   match m.max_offset with
	   | None -> ()
	   | Some(n) -> let _ = get_string m (n-m.offset) in
                        m.max_offset <- None;
	                m.shapes <- []
	   end

  let get_byte m = 
    check m 1;
    let value = int_of_char m.data.[m.offset] in
    m.offset <- m.offset + 1;
    value

  let get_short ?(peak_only=false) m = 
    check m 2;
    let byte0 = int_of_char m.data.[m.offset]
    and byte1 = int_of_char m.data.[m.offset+1] in
    (match peak_only with
    | true -> () (* don't consume the short integer *)
    | false -> m.offset <- m.offset + 2);
    (byte0 lsl 8) lor byte1

  let get_int32 m =
    check m 4;
    let byte0 = Int32.of_int (int_of_char m.data.[m.offset])
    and byte1 = Int32.of_int (int_of_char m.data.[m.offset+1])
    and byte2 = Int32.of_int (int_of_char m.data.[m.offset+2])
    and byte3 = Int32.of_int (int_of_char m.data.[m.offset+3]) in
    let tmp0 = Int32.shift_left byte0 24
    and tmp1 = Int32.shift_left byte1 16
    and tmp2 = Int32.shift_left byte2 8
    in
      m.offset <- m.offset + 4;
      Int32.logor (Int32.logor (Int32.logor tmp0 tmp1) tmp2) byte3

  let get_ip4 m =
    check m 4;
    let byte0 = int_of_char m.data.[m.offset]
    and byte1 = int_of_char m.data.[m.offset+1]
    and byte2 = int_of_char m.data.[m.offset+2]
    and byte3 = int_of_char m.data.[m.offset+3] in
    let tmp = Printf.sprintf "%i.%i.%i.%i" byte0 byte1 byte2 byte3 in
    m.offset <- m.offset + 4;
    tmp

  let get_ip6 m =
    check m 16;
    let tmp = string_to_ip6 (get_string m 16) in
    tmp

  let get_nlri i stoi address_size =
    let plen_bits = get_byte i in
    let plen_bytes = int_of_float(ceil(float_of_int(plen_bits) /. 8.)) in
    let prefix_raw = get_string i plen_bytes in
    let prefix = stoi (nlri_to_ip prefix_raw plen_bits address_size) in
    prefix,plen_bits

  let get_prefixes_list i stoi address_size wr_len =
    let rec internal t =
      match t.max_offset = None || Some(t.offset) < t.max_offset with
      | false -> []
      | true -> let i,p = get_nlri t stoi address_size in
	      (i,p)::(internal t)
    in
      reshape_enter i wr_len;
      let ret = internal i in
      reshape_exit i;
      ret

   let get_list_of_int32 i l =
    let rec internal ii l =
      match l with
      | 0 -> []
      | _ -> let i32 = get_int32 ii in
	     i32::(internal ii (l-1))
    in
      reshape_enter i (4*l);
      let ret = internal i l in
      reshape_exit i;
      ret

  let get_list_of_short i l =
    let rec internal ii l =
      match l with
      | 0 -> []
      | _ -> let i = get_short ii in
	     i::(internal ii (l-1))
    in
      reshape_enter i (2*l);
      let ret = internal i l in
      reshape_exit i;
      ret

  let get_list_of_ip i gip addr_size l =
    let rec internal ii l =
      match l with
      | 0 -> []
      | _ -> let i = gip ii in
	     i::(internal ii (l-1))
    in
      reshape_enter i (addr_size*l);
      let ret = internal i l in
      reshape_exit i;
      ret

  let rec nlri_get_prefixes pc afi stoi ip_len = 
  (* This part of the NLRI BGP attributes is always at the end of the attribute.  *)
    try
      let prefix,plen = get_nlri pc stoi ip_len in
      let ip_address = match afi with
                       | 1 -> IPv4(prefix)
                       | 2 -> IPv6(prefix)
                       | n -> UnknownIP(n) in
      let p = Prefix(ip_address, plen) in
      p::(nlri_get_prefixes pc afi stoi ip_len)
    with
    | ReshapeError(_) -> []

end;;
    

(** Return the module that could be used for parsing according to the file
 * extension. *)
let choose_module filename =
  let has_extension fname ext =
     let ext_len = String.length ext in
     (safe_sub fname ((String.length fname)-ext_len) ext_len) = ext
  in
    match (String.length filename) > 3 with
    | false -> (module InputFile : InputRaw)
    | true  -> match has_extension filename "gz" with
               | true  -> (module InputGzip : InputRaw)
               | false -> (match has_extension filename "bz2" with
                           | true  -> (module InputBz2 : InputRaw)
                           | false -> (module InputFile : InputRaw))
