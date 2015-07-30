%% Copyright (c) 2012, Peter Morgan <peter.james.morgan@gmail.com>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(mdns_node_discovery_server).
-behaviour(gen_server).
-import(proplists, [get_value/2]).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0,
         start_link/1]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link() ->
    start_link([]).

start_link(Parameters) ->
    gen_server:start_link({local, mdns_client:name()}, ?MODULE, Parameters, []).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

-record(state, {socket,
                address,
                domain,
                port,
                interface = {0,0,0,0},
                types = [],
                discovered}).

init(Parameters) ->
    process_flag(trap_exit, true),
    init(Parameters, #state{discovered=dict:new()}).

init([{address, Address} | T], State) ->
    init(T, State#state{address = Address});
init([{interface, IFace} | T], State) ->
    init(T, State#state{interface = IFace});
init([{domain, Domain} | T], State) ->
    init(T, State#state{domain = Domain});
init([{port, Port} | T], State) ->
    init(T, State#state{port = Port});
init([{types, Types} | T], State) ->
    init(T, State#state{types = Types});
init([_ | T], State) ->
    init(T, State);
init([], #state{address = Address, port = Port, interface = IFace} = State) ->
    {ok, Socket} = gen_udp:open(Port, [{mode, binary},
                                       {reuseaddr, true},
                                       {ip, Address},
                                       {multicast_ttl, 4},
                                       {multicast_loop, true},
                                       {broadcast, true},
                                       {add_membership, {Address, IFace}},
                                       {active, once}]),
    timer:send_interval(1000, tick),
    {ok, State#state{socket = Socket}}.

handle_call(discovered, _, #state{discovered = Discovered} = State) ->
    {reply, Discovered, State};

handle_call({discovered, Type}, _, #state{discovered = Discovered} = State) ->
    Res = case dict:find(Type, Discovered) of
              error ->
                  [];
              {ok, Hosts} ->
                  [{Host,  Options} || {Host,  Options, _} <- Hosts]
          end,
    {reply, Res, State};

handle_call(types, _, #state{types = Types} =State) ->
    {reply, {ok, Types}, State};

handle_call(stop, _, State) ->
    {stop, normal, State}.

handle_cast({add_type, Type}, #state{types = Types} = State) ->
    query_service(Type, State),
    {noreply, State#state{types = [Type | Types]}};

handle_cast(_, State) ->
    {noreply, State}.


query_service(Service, #state{domain = Domain, socket = Socket,
                              address = Address, port = Port}) ->
    H = inet_dns:make_header([{id,0},
                              {qr,true},
                              {opcode,'query'},
                              {aa,true},
                              {tc,false},
                              {rd,false},
                              {ra,false},
                              {pr,false},
                              {rcode,0}]),
    Qs = [inet_dns:make_dns_query([{domain, Service ++ Domain},
                                   {class, in},
                                   {type, ptr}])],
    Message = inet_dns:make_msg([{header, H},
                                 {qdlist, Qs}]),
    gen_udp:send(Socket,
                 Address,
                 Port,
                 inet_dns:encode(Message)).

handle_info({nodeup, _}, State) ->
    {noreply, State};

handle_info(tick, #state{discovered=Discovered} = State) ->
    Discovered1 =
        dict:fold(
          fun(Type, V, D) ->
                  dict:store(
                    Type,
                    lists:foldl(
                      fun({Host, Options, TTL}, L) ->
                              case TTL - 1 of
                                  TTL1 when TTL1 =< 0 ->
                                      mdns_node_discovery_event:notify_service_remove(Type, Host, Options),
                                      L;
                                  TTL1 ->
                                      [{Host, Options, TTL1}|L]
                              end
                      end, [], V),
                    D)
          end, dict:new(), Discovered),
    {noreply, State#state{discovered=Discovered1}};


handle_info({udp, Socket, _, _, Packet}, S1) ->
    case inet_dns:decode(Packet) of
        {ok, Record} ->
            Header = inet_dns:header(inet_dns:msg(Record, header)),
            Type = inet_dns:record_type(Record),
            Questions = [inet_dns:dns_query(Query) ||
                            Query <- inet_dns:msg(Record, qdlist)],
            Answers = [inet_dns:rr(RR) || RR <- inet_dns:msg(Record, anlist)],
            Authorities = [inet_dns:rr(RR) || RR <- inet_dns:msg(Record, nslist)],
            Resources = [inet_dns:rr(RR) || RR <- inet_dns:msg(Record, arlist)],
            S2 = handle_record(Header,
                               Type,
                               get_value(qr, Header),
                               get_value(opcode, Header),
                               Questions,
                               Answers,
                               Authorities,
                               Resources,
                               S1),
            inet:setopts(Socket, [{active, once}]),
            {noreply, S2};
        E ->
            lager:error("MDNS error: ~p", E),
            {noreply, S1}
    end.

terminate(_Reason, #state{socket = Socket}) ->
    gen_udp:close(Socket).

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

handle_record(_, msg, false, 'query', [_Question], [], [], [], State) ->
    State;

handle_record(_, msg, false, 'query', [_Question], [_Answer], [], [], State) ->
    State;

handle_record(_, msg, true, 'query', [], Answers, [], Resources, State) ->
    handle_advertisement(Answers, Resources, State);

handle_record(_, _, _, _, _, _, _, _, State) ->
    State.

handle_advertisement([Answer | Answers], Resources, #state{
                                                       domain = Domain,
                                                       discovered = Discovered
                                                      } = State) ->
    {TypeDomain, _, _} = TypeDomainRecord = domain_type_class(Answer),
    case lists:member(TypeDomainRecord, type_domains(State))  of
        true ->
            Res = [{type(Resource), data(Resource)} || Resource <- Resources,
                                                       domain(Resource) =:= data(Answer)],
            {txt, Txt} = lists:keyfind(txt, 1, Res),
            [Type, <<>>] = re:split(TypeDomain, Domain),
            {srv, {_,_,_,
                   Host}} = lists:keyfind(srv, 1, Res),
            Options = parse_txt(Txt),
            case ttl(Answer) of
                0 -> % Remove request
                    Discovered1 =
                        dict:update(
                          Type,
                          fun(Hosts) ->
                                  lists:keydelete(Host, 1, Hosts)
                          end, [], Discovered),
                    mdns_node_discovery_event:notify_service_remove(Type, Host, Options),
                    handle_advertisement(Answers, Resources, State#state{discovered=Discovered1});
                TTL -> % Add request
                    Discovered1 =
                        dict:update(
                          Type,
                          fun(Hosts) ->
                                  lists:keystore(Host, 1, Hosts, {Host, Options, TTL})
                          end, [{Host, Options, TTL}], Discovered),
                    mdns_node_discovery_event:notify_service_add(Type, Host, Options),
                    handle_advertisement(Answers, Resources, State#state{discovered=Discovered1})
            end;
        false ->
            handle_advertisement(Answers, Resources, State)
    end;

handle_advertisement([], _, State) ->
    State.

type_domains(#state{types = Types, domain = Domain}) ->
    [{Type ++ Domain, ptr, in} || Type <- Types].

domain_type_class(Resource) ->
    {domain(Resource), type(Resource), class(Resource)}.

domain(Resource) ->
    get_value(domain, Resource).

type(Resource) ->
    get_value(type, Resource).

class(Resource) ->
    get_value(class, Resource).

data(Resource) ->
    get_value(data, Resource).

ttl(Resource) ->
    get_value(ttl, Resource).

parse_txt(Txts) ->
    [{list_to_atom(binary_to_list(K)), V} ||
        [K, V] <- [re:split(Txt, "=") || Txt <- Txts]].
