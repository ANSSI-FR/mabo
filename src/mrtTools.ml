(* MaBo - MRT tools
 * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
 *
 * This file contains some support functions.
 *)


open Types
open Socket


(** Make sure that String.sub will work *)
let safe_sub str s e =
  match s >= 0 && e <= (String.length str-s) with
  | true -> String.sub str s e
  | false -> raise (SubError(Printf.sprintf"len: %i - start: %i - end: %i" (String.length str) s e))


(** Convert binary data to hex *)
let rec string_to_hexa str =
  match String.length str with
  | 1 ->  Printf.sprintf "%.2x" (int_of_char str.[0])
  | _ -> (Printf.sprintf "%.2x" (int_of_char str.[0]) ) ^ (string_to_hexa (safe_sub str 1 ((String.length str)-1)))


(** Return a string from a list of integers *)
let rec string_list_of_int l =
  match l with
  | i::lst -> (Printf.sprintf "%i " i)^(string_list_of_int lst)
  | [] -> ""


(** Convert a packed IPv4 address to a string *)
let string_to_ip s = Socket.inet_ntop Socket.AF_INET s


(** Convert a packed IPv6 address to a string *)
let string_to_ip6 s = Socket.inet_ntop Socket.AF_INET6 s


(** Expand a NLRI encoded address to a byte boundary *)
let nlri_to_ip raw plen address_size = 
 let expand addr len =
   let n = len-(String.length addr) in
     addr ^ (String.make n (Char.chr 0))
  in
  let rec internal addr plen address_size i =
    match i with
    | n when n == address_size -> safe_sub addr (i-1) 1
    | _                        -> match (i-1)*8 <= plen && plen <= i*8 with
                                  | false -> (safe_sub addr i 1) ^ (internal addr plen address_size (i+1))
				  | true  -> (String.make 1 (Char.chr(int_of_char addr.[i] land (plen mod 8)))) ^ 
				             (internal addr plen address_size (i+1))
    
  in
    internal (expand raw address_size) plen address_size 0


(** Sort a list of MRT dumps from RIS according to their filenames. *)
let sort_mrt_dumps filenames =
  let re = Str.regexp "\\(.*/\\)?\\(updates\\|bview\\)\\.\\([0-9]*\\)\\.\\([0-9]*\\)" in

  (* Extract dates in filenames as integers. *)
  let rec iterate l =
    match l with
    | [] -> []
    | f::lst -> begin
                match Str.string_match re f 0 with
                | true  -> let num = int_of_string ((Str.matched_group 3 f)^(Str.matched_group 4 f)) in
		           [(num*1000 + (int_of_char (Str.matched_group 2 f).[0]), f)]@(iterate lst)

                | false -> iterate lst
	        end
  in
    List.map (fun (x,y) -> y) (List.sort (fun (x1,y1) (x2,y2) -> x1 - x2) (iterate filenames))
