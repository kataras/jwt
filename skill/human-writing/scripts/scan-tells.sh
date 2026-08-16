#!/usr/bin/env bash
# Finds the tells of AI-drafted prose in this repository's markdown.
#
# The PowerShell version next door is the reference implementation. This one exists so the
# check runs on a machine without pwsh, and it applies the same rules to the same corpus.
#
# The two do not report the same totals, and that is expected rather than a bug: grep
# reports a line once per rule, while the PowerShell version reports every match on the
# line. What must agree is which files come back clean. If one of them says zero and the
# other does not, that is worth finding out about.
#
# Fence aware: nothing inside a fenced code block is reported, and inline code spans, link
# targets and bare URLs are blanked before matching, so an identifier or a URL containing a
# double dash is not a finding.
#
# Exit code is 1 while findings remain and 0 when there are none.
#
#   skill/human-writing/scripts/scan-tells.sh book/03-claims.md
#   skill/human-writing/scripts/scan-tells.sh --md
#   skill/human-writing/scripts/scan-tells.sh --md --summary
#   skill/human-writing/scripts/scan-tells.sh --wrap book/

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"

md=0
summary=0
wrap=0
wrap_at=100
paths=()

while [ $# -gt 0 ]; do
  case "$1" in
    --md) md=1 ;;
    --summary) summary=1 ;;
    --wrap) wrap=1 ;;
    --wrap-at) shift; wrap_at="$1" ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) paths+=("$1") ;;
  esac
  shift
done

# Keep this list in step with the Scope section of SKILL.md.
corpus=(book brand skill README.md CHANGELOG.md)

if [ $md -eq 1 ] || [ ${#paths[@]} -eq 0 ]; then
  paths=()
  for p in "${corpus[@]}"; do paths+=("$repo/$p"); done
fi

files=()
for p in "${paths[@]}"; do
  [ -e "$p" ] || continue
  if [ -d "$p" ]; then
    while IFS= read -r f; do files+=("$f"); done < <(find "$p" -name '*.md' -not -path '*/output/*' | sort)
  else
    case "$p" in *.md) files+=("$p") ;; esac
  fi
done

if [ ${#files[@]} -eq 0 ]; then
  echo "scan-tells: nothing to scan"
  exit 0
fi

# rule-name<TAB>extended-regex
rules=$(cat <<'RULES'
em-dash	—
en-dash-prose	[A-Za-z] – [A-Za-z]
ascii-dash	(^|[[:space:]])--([[:space:]]|$)
contraction	[Dd]on'|[Dd]oesn'|[Dd]idn'|[Ii]sn'|[Aa]ren'|[Ww]asn'|[Ww]eren'|[Cc]an'|[Cc]ouldn'|[Ww]on'|[Ww]ouldn'|[Ss]houldn'|[Hh]asn'|[Hh]aven'|[Hh]adn'|[Ii]t'[sd]|[Tt]hat'|[Tt]here'|[Yy]ou'|[Ww]e'|[Tt]hey'|[Ll]et'
buzzword	[Cc]omprehensive|[Rr]obust|[Ss]eamless|[Ss]treamlined|[Ll]everag|[Uu]tiliz|[Ff]acilitat|[Dd]elve|[Pp]lethora|[Mm]yriad|cutting-edge|industry-leading|[Ee]ffortless|game-chang|blazing|ever-evolving|state-of-the-art|battle-tested|testament to|tapestry|treasure trove|[Bb]oasts|[Ee]mpower|[Uu]nleash|[Ss]upercharge
soft-adjective	[Cc]rucial|[Vv]ital|powerful tool|essential tool|significantly improve|highly performant
not-just	isn'. just|is not just|not just a|not only .* but also|more than just
participial	, ensuring|, allowing|, enabling|, empowering|, making it|, providing
dive	[Ll]et'. dive|deep dive|dive into|dive deeper
template	[Pp]rovides? an? (robust|flexible|comprehensive|straightforward|simple|convenient|versatile)|walk you through|[Bb]y (leveraging|understanding|utilizing)|you can ensure that|allows? (you|developers|users) to|allowing (you|developers) to|enables you to|makes it easy to|by following the steps outlined|we will (learn|explore|cover|see)
preamble	[Ii]t is worth noting|[Ii]t'. worth noting|^(Furthermore|Moreover|Additionally)|[Ii]n conclusion|feel free to|as we have seen
section	^#{1,4} +([Cc]onclusion|[Ii]ntroduction|[Oo]verview) *$
admonition	^> *\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]
RULES
)

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

for file in "${files[@]}"; do
  rel="${file#"$repo"/}"

  # Strip fenced blocks and non-prose spans, keeping line numbers intact by emitting a
  # blank line for anything removed.
  awk '
    NR == 1 && $0 == "---" { fm = 1; print ""; next }
    fm { if ($0 == "---") fm = 0; print ""; next }
    /^[[:space:]]*(```|~~~)/ { fence = !fence; print ""; next }
    fence { print ""; next }
    {
      line = $0

      # Multi-backtick spans, before the single form. These may contain single
      # backticks, and awk has no non-greedy match, so they are scanned by hand.
      while (match(line, /``/)) {
        s = RSTART
        rest = substr(line, s + 2)
        if (!match(rest, /``/)) break
        e = s + RSTART + 2
        line = substr(line, 1, s - 1) " " substr(line, e + 1)
      }

      gsub(/`[^`]*`/, " ", line)          # inline code
      gsub(/\]\([^)]*\)/, " ", line)      # link and image targets
      gsub(/https?:\/\/[^ ]+/, " ", line) # bare URLs
      if (line ~ /^[[:space:]]{4,}[^[:space:]]/) line = ""
      print line
    }
  ' "$file" > "$tmp.prose"

  while IFS=$'\t' read -r name pattern; do
    [ -n "$name" ] || continue
    grep -nE "$pattern" "$tmp.prose" 2>/dev/null | while IFS=: read -r lineno rest; do
      printf '%s\t%s:%s\t%s\n' "$name" "$rel" "$lineno" "$(echo "$rest" | sed 's/^[[:space:]]*//')"
    done
  done <<< "$rules" >> "$tmp"
done

rm -f "$tmp.prose"

if [ $wrap -eq 1 ]; then
  count=0
  for file in "${files[@]}"; do
    rel="${file#"$repo"/}"
    while IFS=: read -r lineno len; do
      echo "$rel:$lineno: $len columns"
      count=$((count + 1))
    done < <(awk -v w="$wrap_at" '{ if (length($0) > w) print NR ":" length($0) }' "$file")
  done
  echo
  echo "scan-tells: $count lines over $wrap_at columns in ${#files[@]} files"
  [ "$count" -eq 0 ]
  exit $?
fi

total=$(wc -l < "$tmp" | tr -d ' ')

if [ $summary -eq 1 ]; then
  cut -f1 "$tmp" | sort | uniq -c | sort -rn | awk '{ printf "%-16s %s\n", $2, $1 }'
else
  while IFS=$'\t' read -r name loc text; do
    [ -n "$name" ] || continue
    echo "$loc: $name"
    echo "    $text"
  done < "$tmp"
fi

echo
echo "scan-tells: $total findings in ${#files[@]} files"
[ "$total" -eq 0 ]
