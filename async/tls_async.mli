(** Effectful operations using Lwt for pure TLS.

    The pure TLS is state and buffer in, state and buffer out.  This
    module uses Lwt for communication over the network.

    This module implements a high-level API and a low-level API (in
    {!Unix}).  Most applications should use the high-level API described below. *)

(** [Tls_alert] exception received from the other endpoint *)

open Core.Std
open Async.Std

exception Tls_alert   of Tls.Packet.alert_type

(** [Tls_failure] exception while processing incoming data *)
exception Tls_failure of Tls.Engine.failure

(** tracing of TLS sessions *)
type tracer = Sexplib.Sexp.t -> unit

(** It is the responsibility of the client to handle error
    conditions.  The underlying file descriptors are not closed. *)

(** Abstract type of a session *)
type t

(** {2 Constructors} *)

type 'config make
  = ?tracer:tracer
  -> 'config
  -> app_to_tls:Cstruct.t Pipe.Reader.t
  -> tls_to_app:Cstruct.t Pipe.Writer.t
  -> net_to_tls:Reader.t
  -> tls_to_net:Writer.t
  -> t Deferred.t

val server : Tls.Config.server make
val client : ?host:string -> Tls.Config.client make

(** [reneg t] renegotiates the keys of the session. *)
val reneg : t -> unit Deferred.t

(** [epoch t] returns [epoch], which contains information of the
    active session. *)
val epoch  : t -> (Tls.Types.epoch_data, [`Error]) Result.t
