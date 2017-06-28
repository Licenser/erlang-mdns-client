REBAR = ./rebar3

.PHONY: all compile dialyzer

all: compile dialyzer

compile:
	@$(REBAR) compile

dialyzer:
	@$(REBAR) dialyzer
