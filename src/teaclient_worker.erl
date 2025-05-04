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
    {_,<<PubH:6/binary,_/binary>>}=tpecdsa:cmp_pubkey(Pub),
    Token=maps:get(token, Sub, <<"no-token">>),
    NodeName=maps:get(nodename, Sub, <<(hex:encode(PubH))/binary>>),
    check_ports(Pid, Sub#{pubkey=>Pub,token=>Token,nodename=>NodeName}),
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
      #{null := <<"hello">>,<<"error">> := <<"you_are_late">>} ->
        Error="Sorry. All places in this chain are already taken. In the bot, you can request to participate in another chain.",
        io:format("Server rejects connection, reason:~n  ~s~n~n",[Error]);
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
                io:format("@ ~p", [SE]),
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

check_ports(_Pid, Sub=#{ncp:=true}) ->
  Sub;

check_ports(Pid, Sub=#{token:=Token,nodename:=NodeName,pubkey:=Pub}) ->
  CP=make_ws_req(Pid, #{
                     null=><<"cp">>,
                     pubkey => Pub,
                     token => Token,
                     nodename => NodeName
                    }),
  case CP of
    #{null := <<"cp">>,<<"check">> := true, <<"ports">> :=Ports} ->
      Opened=lists:foldl(fun(P,A) when is_integer(P), P>1024, P<65535 ->
                        R=ranch:start_listener({listener,P},
                                               ranch_tcp,
                                               [ {port, P} ],
                                               cowboy_clear,
                                               #{
                                                 connection_type => supervisor,
                                                 env => #{
                                                          dispatch =>
                                                          cowboy_router:compile([{'_',[{"/",teaclient_http,#{pub=>Pub}}]}])
                                                         }
                                                }
                                              ),
                        io:format("Listen port ~w: ~p~n",[P,R]),
                        A+1;
                       (P,A) ->
                        io:format("Ignore port ~p~n",[P]),
                        A
                    end, 0, Ports),
      if(Opened>0) ->
          io:format("Checking ports, please wait...~n"),
          CP2=make_ws_req(Pid, #{
                                 null=><<"cp2">>,
                                 token => Token,
                                 pubkey => Pub
                                },60000),
          case CP2 of
            #{null := <<"cp2">>, <<"res">> := ResMap } ->
              io:format("Ports checking result:~n",[]),
              maps:foreach(
                fun(K,true) ->
                    io:format(" - Port ~w: ok~n",[K]);
                   (K,V) ->
                    io:format(" - Port ~w: ~s~n",[K,V])
                end,
                ResMap),
              ok;
            _ ->
              io:format("Unexpected answer ~p~n",[CP2])
          end,
          Sub;
        true ->
          Sub
      end;
    _ ->
      Sub
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
      logger:info("ceremony client got ~p",[Cmd]),
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

%handle_msg(#{null := <<"listen_port">>,<<"port">>:=PortNum}, #{privkey:=Priv}=Sub) ->
%  Pub=tpecdsa:calc_pub(Priv),
%  io:format("Port ~w listen request",[PortNum]),
%  R=ranch:start_listener({listener,PortNum},ranch_tcp,
%                       [ {port, PortNum} ],
%                       cowboy_clear,
%                       #{
%                         connection_type => supervisor,
%                         env => #{
%                                  dispatch =>
%                                  cowboy_router:compile([{'_',[{"/",teaclient_http,#{pub=>Pub}}]}])
%                                 }
%                        }
%                      ),
%  io:format(": ~p~n",[R]),
%  Sub;

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

handle_msg(#{null := <<"node_config">>,<<"config">>:=BinCfg}, Sub) ->
  case file:consult("node.config") of
    {ok,[{privkey,PK}]} ->
      file:rename("node.config","node.config_old"),
      file:write_file("node.config",io_lib:format("~s~n~p.~n",[BinCfg,{privkey,PK}])),
      io:format("-=-= [ Config generated ] =-=-~n",[]),
      ok;
    _ ->
      file:write_file("node_example.config",BinCfg),
      io:format("-=-= [ Config template written to node_example.config ] =-=-~n",[]),
      ok
  end,
  Sub;

handle_msg(Msg, Sub) ->
  logger:info("Unhandled msg ~p",[Msg]),
  Sub.
  
make_ws_req(Pid, Request) ->
  make_ws_req(Pid, Request, 5000).

make_ws_req(Pid, Request, Timeout) ->
  receive {gun_ws,Pid, {binary, _}} ->
            throw('unexpected_data')
  after 0 -> ok
  end,
  Cmd = msgpack:pack(Request),
  ok=gun:ws_send(Pid, {binary, Cmd}),
  receive {gun_ws,Pid, _Ref, {binary, Payload}}->
            {ok, Res} = msgpack:unpack(Payload),
            Res
  after Timeout ->
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


