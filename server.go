package main

import (
    "fmt"
    "net/http"
    "html/template"
    "encoding/json"
    "time"
    "github.com/gorilla/mux"
)

type SiteData struct {
    Root string
}

var (
    APIROOT string = "/api"
    ctx SiteData = SiteData{Root: "localhost"}
    tpls = template.Must(template.ParseFiles("tpls/login.html"))
)

func main() {
    fmt.Println("Starting server on port 8080.")
    r := mux.NewRouter()
    r.HandleFunc("/login", getLogin).Methods("GET")
    r.HandleFunc("/login", postLogin).Methods("POST")

    // Static files
    http.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("static"))))

    r.HandleFunc(APIROOT + "/", handleApiRoot).Methods("GET")


    http.Handle("/", r)
    http.ListenAndServe(":8080", nil)
}

type JsonResponse map[string]interface{}

func (r JsonResponse) String() (s string) {
    b, err := json.Marshal(r)
    if err != nil {
        s = ""
        return
    }
    s = string(b)
    return
}

func getLogin(rw http.ResponseWriter, req *http.Request) {
    err := tpls.ExecuteTemplate(rw, "login.html", ctx)
    if err != nil {
        http.Error(rw, err.Error(), http.StatusInternalServerError)
    }
}

func postLogin(rw http.ResponseWriter, req *http.Request) {
    rw.Header().Set("Content-Type", "application/json")
    fmt.Fprint(rw, JsonResponse{"status": "success", "time": time.Now().Format(time.ANSIC)})
    return
}

func handleApiRoot(rw http.ResponseWriter, req *http.Request) {
    rw.Header().Set("Content-Type", "application/json")
    fmt.Fprint(rw, JsonResponse{"status": "active", "time": time.Now().Format(time.ANSIC)})
    return
}

