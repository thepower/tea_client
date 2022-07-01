-module(teaclient).

-export([start/1, main/1]).

main([]) ->
    getopt:usage(option_spec_list(), escript:script_name());
main(Args) ->
  OptSpecList = option_spec_list(),
  case getopt:parse(OptSpecList, Args) of
    {ok, {Options, []}} ->
      application:ensure_all_started(teaclient),
      PArgs=lists:foldl(
              fun({nodename,NN}, Acc) ->
                  Acc#{nodename=>list_to_binary(NN)};
                 ({token,NN}, Acc) ->
                  Acc#{token=>list_to_binary(NN)};
                 ({K,V},Acc) ->
                  Acc#{K=>V}
              end, #{}, Options),
      teaclient_worker:run(PArgs);
    {ok, {Options, NonOptArgs}} ->
      io:format("error: Unexpected arguments~n Options:~n  ~p~n~nNon-option arguments:~n  ~p~n", [Options, NonOptArgs]);
    {error, {Reason, Data}} ->
      io:format("Error: ~s ~p~n~n", [Reason, Data]),
      getopt:usage(OptSpecList, "teaclient")
  end.

option_spec_list() ->
  [
   %% {Name,     ShortOpt,  LongOpt,       ArgSpec,               HelpMsg}
   {host,        $h,    "host",        {string, "ceremony.thepower.io"}, "Seremony server"},
   {port,        $p,    "port",        {integer, 443},       "Ceremony server's TLS port"},
   {nodename,    $n,    "nodename",   string, "node name (max 10 symbols)"},
   {token,      undefined, undefined,     string, "ceremony token"}
  ].
%main([CeremonyID,NodeName]) when is_list(CeremonyID),
%                                  is_list(NodeName) ->
%  start([list_to_binary(CeremonyID),list_to_binary(NodeName)]).

start([CeremonyID,NodeName]) when is_atom(CeremonyID),
                                  is_atom(NodeName) ->
  start([atom_to_binary(CeremonyID),atom_to_binary(NodeName)]);

start([CeremonyID,NodeName]) when is_binary(CeremonyID),
                                  is_binary(NodeName) ->
  application:ensure_all_started(teaclient),
  teaclient_worker:run(CeremonyID,NodeName).
