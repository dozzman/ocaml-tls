open Core.Std
open Async.Std

let ca_cert_dir = "./certificates"
let server_cert = "./certificates/server.pem"
let server_key  = "./certificates/server.key"

let () =
  let port = 4433 in
  let server =
    Log.close (force Log.Global.log);
    Writer.close (force Writer.stdout) >>= fun () ->
    Logs.info (fun f -> f "Closed stdout");
    X509_async.private_of_pems
      ~cert:server_cert
      ~priv_key:server_key >>= fun certificate ->
    Logs.info (fun f -> f "Read certificates");
    let config =
      Tls.Config.(server ~certificates:(`Single certificate)
                    ~ciphers:Ciphers.supported ()) in
    let callback _sock r w : unit Deferred.t =
      Logs.info (fun f -> f "Accepted client");
      let (app_to_tls, app_out) = Pipe.create () in
      let (app_in, tls_to_app) = Pipe.create () in
      Tls_async.server
        (* ~tracer:(fun sexp -> eprintf "%s" (Sexp.to_string_hum sexp)) *)
        config
        ~app_to_tls
        ~tls_to_app
        ~net_to_tls:r
        ~tls_to_net:w
      >>= begin fun _tls ->
        Logs.info (fun f -> f "Started TLS session");
        Pipe.transfer_id app_in app_out >>= fun () ->
        Logs.info (fun f -> f "Ended tls session\n");
        Deferred.all_unit [Reader.close r; Writer.close w]
        (* >>= fun () -> *)
        (* [Writer.stdout ; Writer.stderr] *)
        (* |> Deferred.List.iter ~how:`Parallel ~f:(fun x -> *)
        (*     Writer.flushed (force x)) *)
      end
    in
    Tcp.Server.create (Tcp.on_port port) callback in
  server
  |> Deferred.ignore
  |> don't_wait_for

let () =
  never_returns (Scheduler.go ())
