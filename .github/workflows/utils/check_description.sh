# This script checks that the pull request body matches the patterns
# defined in `description_patterns`. This script will go through
# the body line-by-line, and check that line matches the
# current regex pattern in `description_patterns`. Each regex pattern
# must be matched in order.
#
# Example Description:
# ```
# ## Description
#
# This is a valid PR description.
# ```
# Usage: ./check_description.sh description.txt
description_patterns=("## Description" ".+" "## Convention Checklist")
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

echo 'Please add a description to the PR body with the following format:
## Description

<description>

## Convention Checklist
...
'

exit 1
