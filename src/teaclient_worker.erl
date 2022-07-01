-module(teaclient_worker).
-export([start_link/1,run/1,ws_mode/2,get_privkey/0]).
-export([run/2]).

start_link(Sub) ->
  Pid=spawn(xchain_client_worker,run,[Sub#{parent=>self()}]),
  link(Pid),
  {ok, Pid}.

run(CeremonyID, NodeName) when is_binary(CeremonyID), is_binary(NodeName) ->
  teaclient_worker:run(#{
                         host=>"knuth.cleverfox.ru",
                         port=>1436,
                         token=>CeremonyID,
                         nodename=>NodeName}).

run(#{host:=Ip, port:=Port} = Sub) ->
  process_flag(trap_exit, true),
  try
    CaCerts = certifi:cacerts(),

    logger:info("ceremony client connecting to ~s:~w", [Ip, Port]),
    {ok, Pid} = gun:open(Ip, Port, #{ transport=>tls,
                                    transport_opts => [{verify, verify_peer},
                                                       %{cacertfile,"/usr/local/share/certs/ca-root-nss.crt"}
                                                       {cacerts, CaCerts}
                                                      ]}),
    receive
      {gun_up, Pid, http} ->
        ok
    after 20000 ->
            gun:close(Pid),
            throw('up_timeout')
    end,
    %Proto=case sync_get_decode(Pid, "/xchain/api/compat.mp") of
    %        {200, _, #{<<"ok">>:=true,<<"version">>:=Ver}} -> Ver;
    %        {404, _, _} -> 0;
    %        _ -> 0
    %      end,
    {[<<"websocket">>],UpgradeHdrs}=upgrade(Pid),
    logger:info("Conn upgrade hdrs: ~p",[UpgradeHdrs]),
    Priv=get_privkey(),
    Pub=tpecdsa:calc_pub(Priv,true),
    Token=maps:get(token, Sub, <<"no-token">>),
    NodeName=maps:get(nodename, Sub, <<"noname-",(hex:encode(crypto:strong_rand_bytes(4)))/binary>>),
    R=make_ws_req(Pid, #{
                     null=><<"hello">>,
                     pubkey => Pub,
                     token => Token,
                     nodename => NodeName
                    }),
    %io:format("Hello response is ~p~n",[R]),
    logger:info("Hello response is ~p",[R]),
    case R of
      #{null := <<"hello">>,<<"ok">> := true} ->
        io:format("Connected successfully~n");
      #{null := <<"hello">>,<<"error">> := Error} ->
        io:format("Server rejects connection, reason: ~s~n~n",[Error]),
        timer:sleep(1000)
    end,

    %BlockList=block_list(Pid, Proto, GetFun(chain), last, Known, []),
    %[<<"subscribed">>,_]=make_ws_req(Pid,
    %                                 #{null=><<"subscribe">>,
    %                                   <<"channel">>=>1}
    %                                ),
    %io:format("SubRes ~p~n",[SubRes]),
    %ok=gun:ws_send(Pid, {binary, msgpack:pack(#{null=><<"ping">>})}),
    ws_mode(Pid,Sub#{privkey=>Priv}),
    gun:close(Pid),
    done
  catch
    throw:up_timeout ->
      logger:debug("connection to ~p was timed out", [Sub]),
      timeout;
    Ec:Ee:S ->
          logger:error("ceremony client error ~p:~p",[Ec,Ee]),
          lists:foreach(
            fun(SE) ->
                logger:error("@ ~p", [SE])
            end, S)
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
            {Status, Headers}
  after 10000 ->
          throw(upgrade_timeout)
  end.

get_privkey() ->
  case file:consult("node.config") of
    {ok,List} ->
      case lists:keyfind(privkey,1,List) of
        {privkey, Hex} ->
          hex:decode(Hex);
        false ->
          Priv=tpecdsa:generate_priv(),
          ok=file:write_file("node.config",

                              [ io_lib:format("~p.~n",[X]) ||
                                X<- [ {privkey, binary_to_list(
                                                  hex:encode(Priv)
                                                 )} | List ]
                              ]),
          Priv
      end;
    {error, enoent} ->
      Priv=tpecdsa:generate_priv(),
      ok=file:write_file("node.config",
                         io_lib:format("{privkey, \"~s\"}.~n",
                                       [
                                        hex:encode(Priv)
                                       ])
                        ),
      Priv
  end.


