open Core.Std
open Async.Std

module Async_cstruct = struct
  include Async_cstruct
  let schedule_write w cs =
    Logs.info (fun f -> f "schedule_write %d" (Cstruct.len cs));
    schedule_write w cs
end

exception Tls_alert   of Tls.Packet.alert_type

(** [Tls_failure] exception while processing incoming data *)
exception Tls_failure of Tls.Engine.failure

(** tracing of TLS sessions *)
type tracer = Sexplib.Sexp.t -> unit [@@deriving sexp_of]

type t =
  { app_to_tls: Cstruct.t Pipe.Reader.t
  ; tls_to_app: Cstruct.t Pipe.Writer.t
  ; net_to_tls: Reader.t
  ; tls_to_net: Writer.t
  ; tracer: tracer option
  ; mutable state : [ `Active of Tls.Engine.state
                    | `Eof
                    | `Error of exn ]
  }
  [@@deriving sexp_of]

type 'config make
  = ?tracer:tracer
  -> 'config
  -> app_to_tls:Cstruct.t Pipe.Reader.t
  -> tls_to_app:Cstruct.t Pipe.Writer.t
  -> net_to_tls:Reader.t
  -> tls_to_net:Writer.t
  -> t Deferred.t

let set_state t new_state =
  let s = function
    | `Active s ->
      sprintf "Active %s"
        (match Tls.Engine.epoch s with
         | `InitialEpoch -> "Initial"
         | `Epoch ed -> string_of_int (Caml.Hashtbl.hash ed))
    | `Eof -> "Eof"
    | `Error _ -> "Error" in
  Logs.info (fun f -> f "t.state: %s -> %s\n%!" (s t.state) (s new_state));
  t.state <- new_state

let tracing t f =
  match t.tracer with
  | None      -> f ()
  | Some hook -> Tls.Tracing.active ~hook f

let read_react t cs =
  let handle tls =
    match tracing t (fun () -> Tls.Engine.handle_tls tls cs) with
    | `Ok (state', `Response resp, `Data data) ->
      Logs.info (fun f -> f "handle: `Ok");
      set_state t
        (match state' with
         | `Ok tls  -> `Active tls
         | `Eof     -> `Eof
         | `Alert a -> `Error (Tls_alert a));
      let maybe_reneg =
        match resp with
        | None -> return ()
        | Some r ->
          Async_cstruct.schedule_write t.tls_to_net r;
          Writer.flushed t.tls_to_net in
      let send_to_app =
        match data with
        | None -> return ()
        | Some d -> Pipe.write t.tls_to_app d in
      Deferred.all_unit [maybe_reneg ; send_to_app]
    | `Fail (alert, `Response r) ->
      Logs.info (fun f -> f "handle: `Fail");
      set_state t (`Error (Tls_failure alert));
      Async_cstruct.schedule_write t.tls_to_net r;
      Writer.flushed t.tls_to_net
  in
  match (t.state, Cstruct.len cs) with
  | (`Active tls, _) ->
    handle tls >>| fun () -> `Continue
  | (`Eof, _) ->
    (* TODO tls state terminated but we have more input from the socket? *)
    return (`Stop_consumed ((), 0))
  | (`Error e, _) -> raise e

let tls_read_loop t =
  let handle_chunk bs ~pos ~len =
    Logs.info (fun f -> f "tls_read_loop: read chunk");
    let buf = Cstruct.of_bigarray ~len ~off:pos bs in
    read_react t buf in
  Reader.read_one_chunk_at_a_time t.net_to_tls ~handle_chunk
  >>= begin function
    | `Eof | `Stopped () -> Deferred.unit
    | `Eof_with_unconsumed_data s ->
      Logs.info (fun f -> f "Eof_with_unconsumed_data");
      Cstruct.of_string s
      |> read_react t
      |> Deferred.ignore
  end >>| (fun () ->
      Logs.info (fun f -> f "tls_read_loop: Eof%!");
      set_state t `Eof
    )


let can_handle_appdata t =
  match t.state with
  | `Active s -> Tls.Engine.can_handle_appdata s
  | `Eof
  | `Error _ -> false

let rec app_write_loop t =
  match t.state with
  | `Eof ->
    Logs.info (fun f -> f "app_write_loop: Eof");
    Pipe.close_read t.app_to_tls;
    if not (Pipe.is_empty t.app_to_tls) then
      failwith "Values in pipe left unwritten";
    Deferred.unit
  | `Error e ->
    Pipe.close_read t.app_to_tls;
    raise e
  | `Active tls ->
    if can_handle_appdata t then (
      match Pipe.read_now t.app_to_tls with
      | `Eof ->
        (* TODO update state to Eof? *)
        return ()
      | `Nothing_available ->
        begin Pipe.values_available t.app_to_tls >>= function
          | `Eof -> return () (* TODO update state to Eof? *)
          | `Ok -> app_write_loop t
        end
      | `Ok cs ->
        Logs.info (fun f -> f "app_write_loop: handling app data");
        assert (can_handle_appdata t);
        begin match
            tracing t (fun () -> Tls.Engine.send_application_data tls [cs])
          with
          | Some (tls, tlsdata) ->
            set_state t (`Active tls);
            Async_cstruct.schedule_write t.tls_to_net tlsdata;
            app_write_loop t
          | None -> failwith "socket not ready"
        end
    ) else (
      (* TODO, smarter yield *)
      Scheduler.yield () >>= fun () ->
      app_write_loop t
    )

let conn_loop t =
  Logs.info (fun f -> f "Starting loops");
  Deferred.all_unit [tls_read_loop t; app_write_loop t]

let server ?tracer config ~app_to_tls ~tls_to_app ~net_to_tls ~tls_to_net
  =
  let t =
    { state = `Active (Tls.Engine.server config)
    ; tracer
    ; app_to_tls
    ; tls_to_app
    ; net_to_tls
    ; tls_to_net
    } in
  don't_wait_for (conn_loop t);
  return t

let client ?host ?tracer config ~app_to_tls ~tls_to_app ~net_to_tls
    ~tls_to_net =
  let config =
    match host with
    | None -> config
    | Some host -> Tls.Config.peer config host in
  let (tls, init) = Tls.Engine.client config in
  let t =
    { state = `Active tls
    ; tracer
    ; app_to_tls
    ; tls_to_app
    ; net_to_tls
    ; tls_to_net
    } in
  Async_cstruct.schedule_write t.tls_to_net init;
  Writer.flushed t.tls_to_net >>| begin fun () ->
    don't_wait_for (conn_loop t);
    t
  end


let epoch t =
  match t.state with
  | `Active tls -> ( match Tls.Engine.epoch tls with
      | `InitialEpoch -> assert false (* can never occur! *)
      | `Epoch data   -> Ok data )
  | `Eof      -> Error `Error
  | `Error _  -> Error `Error

let reneg t =
  match t.state with
  | `Error err  -> raise err
  | `Eof        -> failwith "tls: closed socket"
  | `Active tls ->
    match tracing t (fun () -> Tls.Engine.reneg tls) with
    | None -> failwith "tls: can't renegotiate"
    | Some (tls', _buf) ->
      set_state t (`Active tls');
      (* write_t t buf >>= fun () -> *)
      assert false
(* t |> drain_handshake |> Deferred.ignore *)

let () = Nocrypto.Rng.reseed (Cstruct.of_string "010101")

let () =
  ignore (Fmt_tty.setup stderr);
  Logs.set_level (Some Logs.Info);
  let now = Float.to_int (Unix.time ()) in
  let pp_header =
    let open Logs in
    let x = match Array.length Sys.argv with
      | 0 -> Filename.basename Sys.executable_name
      | n -> Filename.basename Sys.argv.(0)
    in
    let pf = Format.fprintf in
    let pp_header ppf (l, h) =
      let elapsed = (Float.to_int (Unix.time ())) - now in
      if l = App then (match h with
          | None -> ()
          | Some h -> pf ppf "[%s] " h) else
        match h with
        | None -> pf ppf "%6d %s: [%a] " elapsed x pp_level l
        | Some h -> pf ppf "%6d %s: [%s] " elapsed x h
    in pp_header
  in
  Logs.set_reporter (Logs_fmt.reporter ~pp_header ())
