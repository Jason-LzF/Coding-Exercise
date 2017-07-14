package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFilter(t *testing.T) {
	vul := vulHandler{}
	var bytes []byte
	err := readFile("vulns.json")
	checkError(err)
	err = dateToTime()
	checkError(err)

	// tests for valid input
	// test1
	r, _ := http.NewRequest("GET", "http://localhost:9999/?limit=12", nil)
	w := httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body := w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test1.json")
	checkError(err)
	if body != fmt.Sprintf("Vulnerabilities are filtered based on: limit=12; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	//test2
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=6&severity_at_least=8", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test2.json")
	checkError(err)
	if body != fmt.Sprintf("Vulnerabilities are filtered based on: severity_at_least=8; limit=6; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test3
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=3&since=2016-07-04", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test3.json")
	checkError(err)
	if body != fmt.Sprintf("Vulnerabilities are filtered based on: limit=3; since=2016-07-04; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test4
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=5&severity_at_least=7&since=2015-12-03", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test4.json")
	checkError(err)
	if body != fmt.Sprintf("Vulnerabilities are filtered based on: severity_at_least=7; limit=5; since=2015-12-03; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test5
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=5&severity_at_least=7&since=2015-12-03&limit=5", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test4.json")
	checkError(err)
	if body != fmt.Sprintf("Vulnerabilities are filtered based on: severity_at_least=7; limit=5; since=2015-12-03; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test6
	r, _ = http.NewRequest("GET", "http://localhost:9999/?severity_at_least=7&limit=5&severity_at_least=7&since=2015-12-03", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test4.json")
	checkError(err)
	if body != fmt.Sprintf("Vulnerabilities are filtered based on: severity_at_least=7; limit=5; since=2015-12-03; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test7
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=5&since=2015-12-03&severity_at_least=7&since=2015-12-03", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test4.json")
	checkError(err)
	if body != fmt.Sprintf("Vulnerabilities are filtered based on: severity_at_least=7; limit=5; since=2015-12-03; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test8
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=5&severity_at_least=7&since=2015-12-03&limit=5&limit=*/.ad", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test4.json")
	checkError(err)
	if body != fmt.Sprintf("Error: 'limit=*/.ad' is invalid\n"+"Vulnerabilities are filtered based on: severity_at_least=7; limit=5; since=2015-12-03; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test9
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=5&severity_at_least=7&severity_at_least=^..&since=2015-12-03&severity_at_least=7", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test4.json")
	checkError(err)
	if body != fmt.Sprintf("Error: 'severity_at_least=^..' is invalid\n"+"Vulnerabilities are filtered based on: severity_at_least=7; limit=5; since=2015-12-03; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test10
	r, _ = http.NewRequest("GET", "http://localhost:9999/?since=2015-12-03&limit=5&severity_at_least=7&since=201c-1b-0a&since=2015-12-03", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns of test4.json")
	checkError(err)
	if body != fmt.Sprintf("Error: 'since=201c-1b-0a' is invalid\n"+"Vulnerabilities are filtered based on: severity_at_least=7; limit=5; since=2015-12-03; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}

	// tests for erroneous/strange input
	// test1: no parameter is specified
	// test2-8: name of parameter is incorrect
	// test9-11: value of parameter is incorrect
	// test12-14: there is more than one valid value of one of parameters
	// test15-19: corner cases
	// test1
	r, _ = http.NewRequest("GET", "http://localhost:9999/?", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test2-8
	// test2
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limat=12", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test3
	r, _ = http.NewRequest("GET", "http://localhost:9999/?sevrity_at_least=7", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test4
	r, _ = http.NewRequest("GET", "http://localhost:9999/?siac'e=2016-02-16", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test5
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limct=1932&sevrity_at_lbast=7", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test6
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limet=1912&siac'/*e=2016-02-16", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test7
	r, _ = http.NewRequest("GET", "http://localhost:9999/?sevrity_at_lbast=7&siac'/*e=2016-02-16", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test8
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limct=1932&sevrity_at_lbast=7&siac'/*e=2016-02-16", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test9-11
	// test9
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=a", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("Error: 'limit=a' is invalid\n"+"There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test10
	r, _ = http.NewRequest("GET", "http://localhost:9999/?severity_at_least=vv/.", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("Error: 'severity_at_least=vv/.' is invalid\n"+"There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test11
	r, _ = http.NewRequest("GET", "http://localhost:9999/?since=8*ad/..", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("Error: 'since=8*ad/..' is invalid\n"+"There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test12-14
	// test12
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=8888&severity_at_least=9&since=2017-01-01&limit=8889", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	if body != fmt.Sprintf("Erroneous input: more than one different limit parameter is found\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test13
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=8888&severity_at_least=9&severity_at_least=7&since=2017-01-01", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	if body != fmt.Sprintf("Erroneous input: more than one different severity_at_least parameter is found\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test14
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=8888&severity_at_least=9&since=2017-01-02&since=2017-01-01", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	if body != fmt.Sprintf("Erroneous input: more than one different since parameter is found\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test15-19
	// test15
	r, _ = http.NewRequest("GET", "http://localhost:9999/?limit=-1", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test16
	r, _ = http.NewRequest("GET", "http://localhost:9999/?severity_at_least=-1", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test17
	r, _ = http.NewRequest("GET", "http://localhost:9999/?severity_at_least=12", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("empty list.json")
	checkError(err)
	if body != fmt.Sprintf("Vulnerabilities are filtered based on: severity_at_least=12; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test18
	r, _ = http.NewRequest("GET", "http://localhost:9999/?severity_at_least=-1", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("vulns for erroneous or strange input.json")
	checkError(err)
	if body != fmt.Sprintf("There is no correct parameter found and the initial list of vulnerabilities is shown below: \n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
	// test19
	r, _ = http.NewRequest("GET", "http://localhost:9999/?since=2020-08-09", nil)
	w = httptest.NewRecorder()
	vul.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("wrong code returned: %d", w.Code)
	}
	body = w.Body.String()
	bytes, err = ioutil.ReadFile("empty list.json")
	checkError(err)
	if body != fmt.Sprintf("Vulnerabilities are filtered based on: since=2020-08-09; \n"+"List of vulnerabilities is shown below:\n"+string(bytes)+"\n") {
		t.Fatalf("wrong body returned: %s", body)
	}
}
