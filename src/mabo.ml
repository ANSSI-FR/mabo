(* MaBo - MRT & BGP command line parser
 * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
 *
 * This file implements differents commands that use different MaBo modules.
 *)


open CommandDump
open CommandPrefixes
open CommandFollow
;;

(** Parse command line arguments and call subcommands *)
let usage = "usage: " ^ Sys.argv.(0)
and usage_subcommands = " {dump,prefixes,follow} ...

Process MRT dumps

Arguments:
  dump                   Dump the content a MRT file
  prefixes               List AS & prefixes in a MRT file
  follow                 Follow a list of IP prefixes in MRT files\n" in


let args_length = Array.length Sys.argv in
match args_length with
  | 0 | 1 -> (Printf.printf "%s" (usage^usage_subcommands); exit 1)
  | _ -> ();

match Sys.argv.(1) with
  | "dump"     -> CommandDump.main usage (Array.sub Sys.argv 1 (args_length-1))
  | "prefixes" -> CommandPrefixes.main usage (Array.sub Sys.argv 1 (args_length-1))
  | "follow"   -> CommandFollow.main usage (Array.sub Sys.argv 1 (args_length-1))
  | _ -> (Printf.printf "%s" (usage^usage_subcommands); exit 1)
