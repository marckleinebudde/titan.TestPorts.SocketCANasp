#!dont_run_this
#
# This file is sourced by */gen_links.sh

gen_link() {
	src="$1"
	f="$2"
	echo "Linking $f"
	ln -sf "$src" "$f"
}

gen_links() {
	DIR=$1
	shift
	FILES=$*
	for f in $FILES; do
		gen_link "$DIR/$f" "$f"
	done
}
