description_patterns=("## Description" ".+" "## Steps to Test" ".+" "## Expected Behaviour" ".+" "## Notes")
target_index=${#description_patterns[@]}
pattern_index=0
lines=$(wc -l < $1)

for ((i=1; i<=lines; i++)); do
    text=$(sed -n -e "${i}p" $1)
    match=$(echo $text | egrep "${description_patterns[$pattern_index]}")

    if [[ -n $match ]]; then
        ((pattern_index++))
        if [[ $pattern_index -eq $target_index ]]; then
            exit 0
        fi
    fi
done

exit 1
