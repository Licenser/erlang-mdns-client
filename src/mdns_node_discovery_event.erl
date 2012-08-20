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

-module(mdns_node_discovery_event).
-export([add_handler/1,
	 add_handler/2,
	 manager/0,
	 notify_service_add/3,
	 notify_service_remove/3]).


manager() ->
    mdns_node_discovery_manager.

add_handler(Handler) ->
    add_handler(Handler, []).

add_handler(Handler, Args) ->
    gen_event:add_handler(manager(), Handler, Args).

notify_service_add(Type, Host, Options) ->
    notify(manager(), {service_add, Type, Host, Options}).

notify_service_remove(Type, Host, Options) ->
    notify(manager(), {service_remove, Type, Host, Options}).


notify(Manager, Message) ->
    gen_event:notify(Manager, Message).

