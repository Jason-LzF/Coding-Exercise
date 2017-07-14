package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"
)

// three date formats used for date parsing
const refDateA = "2006-01-02"
const refDateB = "02/01/2006"
const refDateC = "2006 01 02"

type vulHandler struct{} // http handler

type Vuln struct { // structure for each vulnerability
	Id            int
	Severity      int
	Title         string
	Date_reported string
}

type VulnSlice struct { // vulnerability slice contains multiple vulnerabilities
	Vulns []Vuln
}

type timeStruct struct { // a structure to store time converted from Date_reported of vulnerabilities
	times []time.Time
}

var vulns VulnSlice       // vulns store data of the list of vulnerabilities
var timeOfDate timeStruct // timeOfDate stores time converted from Date_reported of vulnerabilities

func main() {
	err := readFile("vulns.json")
	checkError(err)

	err = dateToTime()
	checkError(err)

	err = http.ListenAndServe(":9999", vulHandler{})
	checkError(err)
}

// readFile loads json objects to a vulnerability slice from the data file
func readFile(filename string) error {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(bytes), &vulns); err != nil {
		return err
	}

	return nil
}

// dateToTime converts dates into time and stores them into the timeOfDate structure with a slice.
// On every request the program can use the time stored in the timeOfDate straightforward for
// date comparison without converting them into time before comparison each time.
func dateToTime() error {
	var ts time.Time
	var err error
	for _, vuln := range vulns.Vulns {
		ts, err = time.Parse(refDateA, vuln.Date_reported)
		if err != nil {
			return err
		}
		timeOfDate.times = append(timeOfDate.times, ts)
	}
	return nil
}

// error handling
func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (vul vulHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// counters for the number of each correct parameter
	sevFound := 0
	limFound := 0
	datFound := 0
	// temp is temporarily obtained value of severity_at_least and limit
	// tempTime is temporarily obtained value of since
	// severity_at_least, limit and since are the correct parameters obtained
	// sevStr, limStr and sinStr store strings of parameters in the map of request
	// invalid records number of failure of a date parsing for a certain date
	var severity_at_least, limit, temp int
	var since, tempTime time.Time
	var err error
	var sevStr, limStr, sinStr string
	var invalid int
	// refDate consists of three different valid input formats of date
	// Since the actual input format of date is unknown, here three usual
	// formats of date are considered as valid. 
	refDate := []string{refDateA, refDateB, refDateC}
	// obtain the correct parameters and deal with erroneous input
	for name, val := range r.URL.Query() {
		switch name {
		case "severity_at_least":
			for i := range val {
				temp, err = strconv.Atoi(val[i])
				if err == nil {
					if temp != severity_at_least && temp > 0 {
						severity_at_least = temp
						sevStr = val[i]
						sevFound++
					}
				} else {
					fmt.Fprintf(w, "Error: 'severity_at_least=%v' is invalid\n", val[i])
				}
				if sevFound > 1 {
					fmt.Fprintf(w, "Erroneous input: more than one different severity_at_least parameter is found\n")
					return
				}
			}
		case "limit":
			for i := range val {
				temp, err = strconv.Atoi(val[i])
				if err == nil {
					if temp != limit && temp >= 0 {
						limit = temp
						limStr = val[i]
						limFound++
					}
				} else {
					fmt.Fprintf(w, "Error: 'limit=%v' is invalid\n", val[i])
				}
				if limFound > 1 {
					fmt.Fprintf(w, "Erroneous input: more than one different limit parameter is found\n")
					return
				}
			}
		case "since":
			for i := range val {
				for j := range refDate {
					tempTime, err = time.Parse(refDate[j], val[i])
					if err == nil {
						if tempTime != since {
							since = tempTime
							sinStr = val[i]
							datFound++
							break
						}
					} else {
						invalid++
					}
				}
				if invalid == 3 {
					invalid = 0
					fmt.Fprintf(w, "Error: 'since=%v' is invalid\n", val[i])
				}
				if datFound > 1 {
					fmt.Fprintf(w, "Erroneous input: more than one different since parameter is found\n")
					return
				}
			}
		}
	}
	if totalFound := sevFound + limFound + datFound; totalFound == 0 {
		fmt.Fprintf(w, "There is no correct parameter found and the initial list of vulnerabilities is shown below: \n")
		voB, err := json.Marshal(vulns)
		checkError(err)
		fmt.Fprintf(w, "%v\n", string(voB))
		return
	}

	// print out information of valid parameters
	fmt.Fprintf(w, "Vulnerabilities are filtered based on: ")
	if sevFound == 1 {
		fmt.Fprintf(w, "severity_at_least=%s; ", sevStr)
	}
	if limFound == 1 {
		fmt.Fprintf(w, "limit=%s; ", limStr)
	}
	if datFound == 1 {
		fmt.Fprintf(w, "since=%s; ", sinStr)
	}
	fmt.Fprintf(w, "\nList of vulnerabilities is shown below:\n")
	// filter out vulnerabilities based on parameters of input
	vo := new(VulnSlice)
	satisfy := condition(sevFound, datFound, severity_at_least, since)
	if limFound == 0 {
		vo = filterWithoutLimit(satisfy)
	} else {
		vo = filterWithLimit(limit, satisfy)
	}

	// response with a list of vulnerabilities to the web browser
	b, err := json.Marshal(*vo)
	checkError(err)
	fmt.Fprintf(w, "%v\n", string(b))
}

// condition generates a function to determine whether a vulnerability satisfy the input parameters
// based on the correct parameters collected. For example, if only severity_at_least is specified,
// it will return a function which only checks if the Severity of a vulnerability is greater than
// or equal to severity_at_least without checking any other parameters.
func condition(sevFound int, datFound int, severity_at_least int, since time.Time) func(i int) bool {
	if sevFound == 1 && datFound == 0 {
		return func(i int) bool {
			return vulns.Vulns[i].Severity >= severity_at_least
		}
	} else if sevFound == 0 && datFound == 1 {
		return func(i int) bool {
			return timeOfDate.times[i].After(since) || timeOfDate.times[i].Equal(since)
		}
	} else if sevFound == 1 && datFound == 1 {
		return func(i int) bool {
			return vulns.Vulns[i].Severity >= severity_at_least && (timeOfDate.times[i].After(since) || timeOfDate.times[i].Equal(since))
		}
	} else {
		return func(i int) bool {
			return true
		}
	}
}

// filterWithoutLimit filters out vulnerabilities without
// limit parameter being specified and return with a
// structure containing a slice of vulnerabilities
func filterWithoutLimit(f func(i int) bool) *VulnSlice {
	vo := new(VulnSlice)
	for i, vuln := range vulns.Vulns {
		if f(i) {
			vo.Vulns = append(vo.Vulns, vuln)
		}
	}

	return vo
}

// filterWithoutLimit filters out vulnerabilities with
// limit parameter being specified and return with a
// structure containing a slice of vulnerabilities
func filterWithLimit(limit int, f func(i int) bool) *VulnSlice {
	vo := new(VulnSlice)
	for i, vuln := range vulns.Vulns {
		if len(vo.Vulns) > limit-1 {
			break
		}
		if f(i) {
			vo.Vulns = append(vo.Vulns, vuln)
		}
	}

	return vo
}
