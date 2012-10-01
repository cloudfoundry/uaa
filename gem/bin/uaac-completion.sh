#/bin/sh
GLOBAL_OPTS="--help --no-help -h --version --no-version -v --debug --no-debug -d --trace --no-trace -t --config"

_debug() {
	if [[ $UAAC_DEBUG -eq 1 ]] ; then
		echo "$@;"
	fi	
}

_add_completion_options() {
	local current="${COMP_WORDS[${COMP_CWORD}]}"
	COMPREPLY=( "${COMPREPLY[@]}" $(compgen -W "$1" -- $current) )
}

_uaac() {
	local current="${COMP_WORDS[${COMP_CWORD}]}"
	local helper_input=()
	if [[ "$current" == "" ]] || [[ "$current" == " " ]] || [[ $current == -* ]] ; then
		helper_input=( ${COMP_WORDS[@]} )
	else
		helper_input=( ${COMP_WORDS[@]/$current/} )
	fi
	
	local parent_command="${COMP_WORDS[0]}"
	local uaac_opts=$(completion-helper "${parent_command}" "${helper_input[@]}")
	local opts=$uaac_opts
	if [[ $current == -* ]] ; then
		opts="${GLOBAL_OPTS} ${uaac_opts}"		
	fi
	_add_completion_options "${opts}"
	
}

complete -F _uaac uaac