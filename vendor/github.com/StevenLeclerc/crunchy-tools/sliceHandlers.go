package crunchyTools

import (
	"regexp"
	"strings"
)

//We permute the last value with the index to delete, then we return the array without the last element
func RemoveIdFromArray(arrayToUpdate interface{}, indexToRemove int) (result interface{}) {
	switch arrayToUpdate := arrayToUpdate.(type) {
	case []string:
		arrayToUpdate[len(arrayToUpdate)-1], arrayToUpdate[indexToRemove] = arrayToUpdate[indexToRemove], arrayToUpdate[len(arrayToUpdate)-1]
		result = arrayToUpdate[:len(arrayToUpdate)-1]
	}
	return
}

//CleanSlice will delete empty or whitespace string or from slice
func CleanSlice(stringToHandle []string) []string {
	for key, value := range stringToHandle {
		isEmpty, errRegex := regexp.MatchString("^$|\\s+", value)
		HasError(errRegex, "Armory - sliceHelpers - CleanSlice", false)
		if isEmpty {
			stringToHandle = append(stringToHandle[:key], stringToHandle[key+1:]...)
			stringToHandle = CleanSlice(stringToHandle)
			break
		}
	}
	return stringToHandle
}

//CompareSlice compare if the slice 1 is deeply equal to slice 2 without use of reflect.DeepEqual
func CompareSlice(sliceOne []string, sliceTwo []string) bool {
	isExist := false
	if len(sliceOne) == len(sliceTwo) {
		for _, valueRemote := range sliceOne {
			for _, valueLocal := range sliceTwo {
				if valueRemote == valueLocal {
					isExist = true
				}
			}
			if !isExist {
				return false
			}
		}
		return true
	}
	return false
}

//JoinSlicesToString return a string from merged slice with sperator
func JoinSlicesToString(sliceTojoin []string, separator string) string {
	return strings.Join(sliceTojoin, separator)
}

//CompareSliceValues check if the value inside ReferenceSlice are present in sliceToCheck
func CompareSliceValues(referentSlice []string, sliceToCkech []string) bool {
	isExist := false
	for _, valueRemote := range referentSlice {
		for _, valueLocal := range sliceToCkech {
			if valueRemote == valueLocal {
				isExist = true
			}
		}
		if !isExist {
			return false
		}
	}
	return true
}

//ContainValueInSlice tells whether a contains x.
func ContainValueInSlice(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
