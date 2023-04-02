package kfl

// Validate tries to parse the given query and checks if there are
// any syntax errors or not.
func Validate(query string) (err error) {
	// Expand all macros in the query, if there are any.
	query, err = ExpandMacros(query)
	if err != nil {
		return
	}
	_, err = Parse(query)
	return
}
