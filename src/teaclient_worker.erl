-module(teaclient_worker).
-export([start_link/1,run/1,ws_mode/2,get_privkey/1]).
-export([run/2]).

start_link(Sub) ->
  Pid=spawn(xchain_client_worker,run,[Sub#{parent=>self()}]),
  link(Pid),
  {ok, Pid}.

run(CeremonyID, NodeName) when is_binary(CeremonyID), is_binary(NodeName) ->
  teaclient_worker:run(#{
                         host=>"tea.thepower.io",
                         port=>1436,
                         token=>CeremonyID,
                         nodename=>NodeName}).

run(#{host:=Ip, port:=Port} = Sub) ->
  process_flag(trap_exit, true),
  CaCerts = certifi:cacerts(),

  CHC=[
       {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
      ],

  logger:info("ceremony client connecting to ~s:~w", [Ip, Port]),
  io:format("ceremony client connecting to ~s:~w~n", [Ip, Port]),
  {ok, Pid} = gun:open(Ip, Port, #{ transport=>tls,
                                    protocols => [http],
                                    transport_opts => [{verify, verify_none},
                                                       {depth, 5},
                                                       {customize_hostname_check, CHC},
                                                       %{cacertfile,"/usr/local/share/certs/ca-root-nss.crt"}
                                                       {cacerts, CaCerts}
                                                      ]}),
  try
    receive
      {gun_up, Pid, _HTTP} ->
        ok;
      {gun_down, Pid, _Protocol, closed, _, _} ->
        throw(up_error)
    after 5000 ->
            throw('up_timeout')
    end,
    {[<<"websocket">>],UpgradeHdrs}=upgrade(Pid),
    logger:info("Conn upgrade hdrs: ~p",[UpgradeHdrs]),
    Priv=get_privkey(Sub),
    Pub=case maps:is_key(legacy,Sub) of
          true ->
            tpecdsa:calc_pub(Priv,true);
          false ->
            tpecdsa:calc_pub(Priv,true)
        end,
    Token=maps:get(token, Sub, <<"no-token">>),
    NodeName=maps:get(nodename, Sub, <<"noname-",(hex:encode(crypto:strong_rand_bytes(4)))/binary>>),
    R=make_ws_req(Pid, #{
                     null=><<"hello">>,
                     pubkey => Pub,
                     token => Token,
                     nodename => NodeName
                    }),
    logger:info("Hello response is ~p",[R]),
    case R of
      #{null := <<"hello">>,<<"ok">> := true} ->
        io:format("Connected successfully~n"),
        ws_mode(Pid,Sub#{privkey=>Priv});
      #{null := <<"hello">>,<<"error">> := Error} ->
        io:format("Server rejects connection, reason: ~s~n~n",[Error])
    end,

    gun:close(Pid),
    done
  catch
    throw:up_timeout ->
      io:format("connection to ~p was timed out~n", [Sub]),
      logger:error("connection to ~p was timed out", [Sub]),
      up_timeout;
    throw:Ee:S ->
      gun:close(Pid),
      io:format("ceremony client error ~p~n",[Ee]),
      logger:error("ceremony client error ~p",[Ee]),
          lists:foreach(
            fun(SE) ->
                logger:error("@ ~p", [SE])
            end, S),
          Ee;
    Ec:Ee:S ->
      gun:close(Pid),
          io:format("ceremony client error ~p:~p~n",[Ec,Ee]),
          logger:error("ceremony client error ~p:~p",[Ec,Ee]),
          lists:foreach(
            fun(SE) ->
                logger:error("@ ~p", [SE])
            end, S),
          {Ec,Ee}
  end.

ws_mode(Pid,Sub) ->
  receive
    {'EXIT',_,shutdown} ->
      Cmd = msgpack:pack(#{null=><<"goodbye">>, <<"r">>=><<"shutdown">>}),
      gun:ws_send(Pid, {binary, Cmd}),
      gun:close(Pid),
      exit;
    {'EXIT',_,normal} ->
      Cmd = msgpack:pack(#{null=><<"goodbye">>, <<"r">>=><<"normal">>}),
      gun:ws_send(Pid, {binary, Cmd}),
      gun:close(Pid),
      exit;
    {'EXIT',_,Reason} ->
      logger:error("Linked process went down ~p. Giving up....",[Reason]),
      Cmd = msgpack:pack(#{null=><<"goodbye">>, <<"r">>=><<"deadparent">>}),
      gun:ws_send(Pid, {binary, Cmd}),
      gun:close(Pid),
      exit;
    {state, CPid} ->
      CPid ! {Pid, Sub},
      ?MODULE:ws_mode(Pid, Sub);
    stop ->
      Cmd = msgpack:pack(#{null=><<"goodbye">>, <<"r">>=><<"stop">>}),
      gun:ws_send(Pid, {binary, Cmd}),
      gun:close(Pid),
      done;
%    {send_msg, Payload} ->
%      Cmd = msgpack:pack(Payload),
%      gun:ws_send(Pid, {binary, Cmd}),
%      ?MODULE:ws_mode(Pid, Sub);
    {gun_ws, Pid, _Ref, {binary, Bin}} ->
      {ok,Cmd} = msgpack:unpack(Bin),
      logger:debug("ceremony client got ~p",[Cmd]),
      Sub1=handle_msg(Cmd, Sub#{pid=>Pid}),
      %Sub1=xchain_client_handler:handle_xchain(Cmd, Pid, Sub),
      ?MODULE:ws_mode(Pid, Sub1);
    {gun_ws,Pid,_Ref,{text,Text}} ->
      logger:info("Peer told ~p",[Text]),
      ?MODULE:ws_mode(Pid, Sub);
    {gun_down,Pid,ws,closed,_,_} ->
      logger:error("Gun down. Giving up...."),
      giveup;
    Any ->
      logger:notice("ceremony client unknown msg ~p",[Any]),
      ?MODULE:ws_mode(Pid, Sub)
  after 3000 ->
          ok=gun:ws_send(Pid, {binary, msgpack:pack(#{null=><<"ping">>})}),
          ?MODULE:ws_mode(Pid, Sub)
  end.

handle_msg(#{null := <<"signtx">>,<<"patchtx">>:=BinTx}, #{pid:=Pid, privkey:=Priv}=Sub) ->
  %Priv=tpecdsa:generate_priv(),
  #{ver:=2,kind := patch, sig:=[]}=Tx=tx:unpack(BinTx),
  logger:info("Tx ~p",[Tx]),
  #{sig:=[Signature]}=tx:sign(Tx,Priv),
  logger:info("Signature ~p",[Signature]),
  ok=gun:ws_send(Pid, {binary, msgpack:pack(#{null=><<"signtx_ack">>, signture=>Signature})}),
  Sub;

handle_msg(#{null := <<"signblk">>,<<"block">>:=BinBlock}, #{pid:=Pid, privkey:=Priv}=Sub) ->
  Block=block:unpack(BinBlock),
  #{sign:=[Signature]}=block:sign(maps:remove(sign,Block),Priv),
  logger:info("Signature ~p",[Signature]),
  ok=gun:ws_send(Pid, {binary, msgpack:pack(#{null=><<"signblk_ack">>, signture=>Signature})}),
  Sub;

handle_msg(#{null := <<"progress">>,<<"step">>:=Step, <<"goal">> := Req,<<"got">> := Got}=M, Sub) ->
  TStep = case Step of
            1 -> "waiting for all nodes";
            2 -> "waiting for patch signatures";
            3 -> "waiting for block signatures";
            4 -> "ready"
          end,
  case(M=/=maps:get(lastprogress,Sub,undef)) of
    true ->
      io:format("== [step ~w (~s) ~w% ] == ~n",[Step, TStep, (100*Got) div Req]);
    false -> ok
  end,
  Sub#{lastprogress=>M};

handle_msg(#{null := <<"genesis">>,<<"block">>:=BinBlock}, Sub) ->
  #{hash:=H}=Block=block:unpack(BinBlock),
  file:write_file("genesis.txt",io_lib:format("~p.~n",[Block])),
  {true,_} = block:verify(Block),
  io:format("-=-= [ Cerenomy done ] =-=-~n",[]),
  io:format("=== [ Genesis hash ~s ] === ~n",[hex:encode(H)]),
  init:stop(),
  Sub;

handle_msg(Msg, Sub) ->
  logger:info("Unhandled msg ~p",[Msg]),
  Sub.
  
make_ws_req(Pid, Request) ->
  receive {gun_ws,Pid, {binary, _}} ->
            throw('unexpected_data')
  after 0 -> ok
  end,
  Cmd = msgpack:pack(Request),
  ok=gun:ws_send(Pid, {binary, Cmd}),
  receive {gun_ws,Pid, _Ref, {binary, Payload}}->
            {ok, Res} = msgpack:unpack(Payload),
            Res
  after 5000 ->
          throw('ws_timeout')
  end.

upgrade(Pid) ->
  gun:ws_upgrade(Pid, "/api/ws",
                 [ {<<"sec-websocket-protocol">>, <<"thepower-tea-ceremony-v1">>} ]),
  receive {gun_upgrade,Pid,_Ref,Status,Headers} ->
            {Status, Headers};
          {gun_down, Pid, _Protocol, closed, [], []} ->
            gun:close(Pid),
            throw(upgrade_error);
          {gun_response, Pid, _Ref, _Fin, ErrorCode, _Headers} ->
            gun:close(Pid),
            throw({upgrade_error, ErrorCode})
  after 5000 ->
          gun:close(Pid),
          throw(upgrade_timeout)
  end.

get_privkey(Sub) ->
  Priv=case maps:is_key(legacy,Sub) of
         false -> tpecdsa:generate_priv(ed25519);
         true -> tpecdsa:generate_priv()
       end,
  case file:consult("node.config") of
    {ok,List} ->
      case lists:keyfind(privkey,1,List) of
        {privkey, Hex} ->
          hex:decode(Hex);
        false ->
          ok=file:write_file("node.config",
                              [ io_lib:format("~p.~n",[X]) ||
                                X<- [ {privkey, binary_to_list(
                                                  hex:encode(Priv)
                                                 )} | List ]
                              ]),
          Priv
      end;
    {error, enoent} ->
      ok=file:write_file("node.config",
                         io_lib:format("{privkey, \"~s\"}.~n",
                                       [
                                        hex:encode(Priv)
                                       ])
                        ),
      Priv
  end.


