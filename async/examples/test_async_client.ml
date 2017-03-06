open Core.Std
open Async.Std

let test_client () =
  let port = 4433 in
  let host = "127.0.0.1" in
  X509_async.authenticator `No_authentication_I'M_STUPID
  >>= fun authenticator ->
  Logs.info (fun f -> f "Authentication");
  Tcp.(connect (to_host_and_port host port)) >>= fun (_sock, r, w) ->
  Logs.info (fun f -> f "Connected to %s:%d" host port);
  let config =
    Tls.Config.(client ~authenticator ~ciphers:Ciphers.supported ()) in
  let (app_in, tls_to_app) = Pipe.create () in
  let (app_to_tls, app_out) = Pipe.create () in
  Tls_async.client config
    (* ~tracer:(fun sexp -> eprintf "%s" (Sexp.to_string_hum sexp)) *)
    ~app_to_tls
    ~tls_to_app
    ~net_to_tls:r
    ~tls_to_net:w >>= fun _tls ->
  Logs.info (fun f -> f "Started TLS connection");
  let req = String.concat ~sep:"\r\n" [
      "GET / HTTP/1.1" ; "Host: " ^ host ; "Connection: close" ; "" ; ""
    ] in
  Pipe.write app_out (Cstruct.of_string req) >>= fun () ->
  Logs.info (fun f -> f "Written request. Waiting for response");
  Pipe.read app_in >>| begin fun x ->
    begin match x with
      | `Eof -> failwith "uh oh"
      | `Ok a -> printf "%s++done.\n%!" (Cstruct.to_string a)
    end;
    Logs.info (fun f -> f "Closing TLS Connection");
    Pipe.close tls_to_app;
    Pipe.close_read app_to_tls
  end

let () =
  Command.run (Command.async ~summary:"" Command.Spec.empty test_client)
