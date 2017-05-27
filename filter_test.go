package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// This test program consisits of 3 tests for different types of erroneous input
// uncomment one of the testFilter functions below and comment the remaining test functions to test the http handler
// only one test function works each time

// test 1
// test for erroneous name of parameters
// erroneous name of parameter: "limat" 
func TestFilter1(t *testing.T) {
	// We first create the http.Handler we wish to test
	vul := vulHandler{}

    // We can change any of the names of parameters to test the http handler
    r, _ := http.NewRequest("GET","http://www.vulns.com/?limat=12&severity_at_least=8&since=2015-01-03", nil)
	w := httptest.NewRecorder()

	vul.ServeHTTP(w, r)
    
	// Here we check the response code
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}

	// check its contents are what we expect
	body := w.Body.String()
	if body != fmt.Sprintf("erroneous input: missing parameters\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
}

// test 2
// test for erroneous number of values of parameters. For instance, there are more than one limit values.
// 2 "limit" in the http request
/*func TestFilter2(t *testing.T) {
	// We first create the http.Handler we wish to test
	vul := vulHandler{}

    r, _ := http.NewRequest("GET","http://www.vulns.com/?limit=2&severity_at_least=8&since=2015-01-03&limit=3", nil)
	w := httptest.NewRecorder()

	vul.ServeHTTP(w, r)
    
	// Here we check the response code
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}

	// check its contents are what we expect
	body := w.Body.String()
	//fmt.Printf("%v\n", body)
	if body != fmt.Sprintf("erroneous input: too many values of parameters\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
}*/

// test 3
// test for erroneous value of parameters
// erroneous value of parameter "since": "2015-a1-c3"
/*func TestFilter3(t *testing.T) {
	// We first create the http.Handler we wish to test
	vul := vulHandler{}

    r, _ := http.NewRequest("GET","http://www.vulns.com/?limit=2&severity_at_least=8&since=2015-a1-c3", nil)
	w := httptest.NewRecorder()

	vul.ServeHTTP(w, r)
    
	// Here we check the response code
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}

	// check its contents are what we expect
	body := w.Body.String()
	if body != fmt.Sprintf("erroneous input: invalid value of parameter\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
}*/
