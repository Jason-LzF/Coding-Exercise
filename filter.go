package main

import (
	"fmt"
	"log"
	"net/http"
	"encoding/json"
	"strings"
	"strconv"
    "io/ioutil"
    "os"
)

const lengthOfDateStr = 10     // length of a string of date from valid input
const numberOfVulns = 10000    // number of vulnerabilities in the initial list


var err bool  // error indication: false if no error, otherwise true

type vulHandler struct{}  // http handler

type Vuln struct{  // structure for each vulnerability
	Id int
	Severity int
	Title string
	Date_reported string
}

type VulnSlice struct{  // vulnerability slice contains multiple vulnerabilities
	Vulns []Vuln
}

type date struct{  // structure for a date
	year int
	month int
	day int
}

// ServeHTTP handles http request from user and filter out vulnerabilities 
// based on the provided parameters from http request. It also handles 
// different types of erroneous/strange input appropriately. 
func (vul vulHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // counter for the number of each valid parameter
    sevCounter := 0    
    limitCounter := 0
    sinceCounter := 0

    // obtain parameters in http request and check the name of each parameter
 	mapOfRequest := r.URL.Query()
    for name, _ := range mapOfRequest {
    	if strings.Index("severity_at_least", name) == 0 && len(name) == len("severity_at_least") {
    		sevCounter = 1
    	}
        if strings.Index("limit", name) == 0 && len(name) == len("limit") {
    		limitCounter = 1
    	}
    	if strings.Index("since", name) == 0 && len(name) == len("since") {
    		sinceCounter = 1
    	}
    }
    if sevCounter != 1 || limitCounter != 1 || sinceCounter != 1 {
    	err = true
    	fmt.Fprintf(w, "erroneous input: missing parameters\n")
    }

    // if there is no error in the name of parameters, check the number of occurrence of each parameter
    if !err {
    	if len(mapOfRequest["severity_at_least"]) != 1 || len(mapOfRequest["limit"]) != 1 || len(mapOfRequest["since"]) != 1 {
    		err = true
    		fmt.Fprintf(w, "erroneous input: too many values of parameters\n")
    	}
    }
    
    // if there is no error, check the value of each parameter
    if !err {
    	sevStr := strings.Join(mapOfRequest["severity_at_least"], "")
	    limitStr := strings.Join(mapOfRequest["limit"], "")
	    dateStr := strings.Join(mapOfRequest["since"], "")

	    _, err4 := strconv.Atoi(sevStr)
	    _, err5 := strconv.Atoi(limitStr)
	    var refDate date
		dateStrToStruct(dateStr , &refDate)
		if err == true || err4 != nil || err5 != nil {
			err = true
			fmt.Fprintf(w, "erroneous input: invalid value of parameter\n")
		}
    }
	
    // if there is no error, start filtration of vulnerabilities
	if !err {
		var vi VulnSlice  // to store input from a data file 
		var vo VulnSlice  // to store output to the response 
        err6 := readFile("vulns.json", &vi)
        if err6 != nil {
            os.Exit(3)
        }

	    var dateS date
	    var refDate date
	    sevStr := strings.Join(mapOfRequest["severity_at_least"], "")
	    limitStr := strings.Join(mapOfRequest["limit"], "")
	    dateStr := strings.Join(mapOfRequest["since"], "")

	    severity_at_least, _ := strconv.Atoi(sevStr)
	    limit, _ := strconv.Atoi(limitStr)
	    dateStrToStruct(dateStr , &refDate)

		i, j := 0, 0
	    for i < numberOfVulns && j < limit {
	    	dateStrToStruct(vi.Vulns[i].Date_reported ,&dateS)
	    	if vi.Vulns[i].Severity >= severity_at_least && isAfterRefDate(dateS, refDate) {
	    		vo.Vulns = append(vo.Vulns, vi.Vulns[i])
	    		j++
	    	}
	    	i++
	    }
	    b, _ := json.Marshal(vo)
	    fmt.Fprintf(w, "%v\n", string(b))
	}
}

// A web server 
// more details on how to use it refer to the instruction file
func main() {
	err4 := http.ListenAndServe(":9999", vulHandler{})
	log.Fatal(err4)
}

// readFile loads json objects to a vulnerability slice from the data file
func readFile(filename string, vi *VulnSlice) error {
    bytes, err6 := ioutil.ReadFile(filename)
    if err6 != nil {
        fmt.Println("ReadFile: ", err6.Error())
        return err6
    }
 
    if err6 := json.Unmarshal([]byte(bytes), &vi); err6 != nil {
        fmt.Println("Unmarshal: ", err6.Error())
        return err6
    }
 
    return nil
}

// dateStrToStruct converts a date string to a structure of date
func dateStrToStruct(dateStr string, dateStrut *date) {
	if len(dateStr) != lengthOfDateStr {   
		err = true
		dateStrut.year = 0
		dateStrut.month = 0
		dateStrut.day = 0
	}  else {
		yearStr := dateStr[0:4]    // valid input format of date like "2015-12-03", "2015 3 16", "2015,06,12"
		monthStr := dateStr[5:7]   // there has to be one charactor between each number
		dayStr := dateStr[8:10]    // the order has to be "year-month-day"

		year, err1 := strconv.Atoi(yearStr)    // if any of err1, err2, err3 != nil, the input of date is erroneous
		month, err2 := strconv.Atoi(monthStr)
		day, err3 := strconv.Atoi(dayStr)
		if err1 == nil && err2 == nil && err3 == nil {
			if year >= 1000 && month != 0 && day != 0 {
				dateStrut.year = year
				dateStrut.month = month
				dateStrut.day = day
			} else {
				err = true
				dateStrut.year = 0
				dateStrut.month = 0
				dateStrut.day = 0
			}
		} else {
			err = true
			dateStrut.year = 0
			dateStrut.month = 0
			dateStrut.day = 0
		}
	}
}

// isAfterRefDate determines whether the date_reported of a vulnerability is 
// after the reference date, where reference date is the date from "since" 
// parameter from http request.
func isAfterRefDate(dateS date, refDate date) bool {
	if dateS.year >= refDate.year {
		if dateS.month >= refDate.month {
			if dateS.day >= refDate.day {
				return true
			} else {
				return false
			}
		} else {
			return false
		}
	} else {
		return false
	}
}
