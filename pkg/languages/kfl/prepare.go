package kfl

import (
	"github.com/rs/zerolog/log"
)

// Apply does these steps:
// - Expand the macros in given query.
// - Parse the query.
// - Precompute the values in the query.
// - Evaluate the expression.
// and returns:
// - Truthiness of the record for the given query.
// - The new record that's altered by the query.
// - Error if any step ends with an error, otherwise nil.
func Apply(b []byte, query string) (truth bool, record string, err error) {
	var expr *Expression
	// Prepare the query.
	expr, _, err = PrepareQuery(query)
	if err != nil {
		log.Error().Err(err).Send()
		return
	}

	truth, record, err = Eval(expr, string(b))
	if err != nil {
		log.Error().Err(err).Msg("Eval error:")
		return
	}

	return
}

func PrepareQuery(query string) (expr *Expression, prop Propagate, err error) {
	// Expand all macros in the query, if there are any.
	query, err = ExpandMacros(query)
	if err != nil {
		log.Error().Err(err).Msg("Macro expand error:")
		return
	}

	// Parse the query.
	expr, err = Parse(query)
	if err != nil {
		log.Error().Err(err).Msg("Syntax error:")
		return
	}

	prop, err = Precompute(expr)
	if err != nil {
		log.Error().Err(err).Msg("Precompute error:")
	}

	return
}
