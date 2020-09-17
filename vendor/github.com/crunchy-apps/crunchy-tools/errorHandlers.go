package crunchyTools

import (
	"fmt"
)

//HasError Checks if the first arg is set, you must provide some context and set the silent mode. However you can choose to run a function if a error is detected, this function
// will inject a string parameter with the detail of the error
func HasError(err error, context string, silent bool, lastFunction ...func(data string)) error {
	if err != nil {
		logger := FetchLogger()
		errorMessage := fmt.Sprintf("Error in %s: %s\n", context, err)
		if len(lastFunction) > 0 {
			lastFunction[0](errorMessage)
		}
		if !silent {
			logger.Err.Fatalf(errorMessage)
		}
		logger.Warn.Print(errorMessage)
		return err
	}
	return nil
}
