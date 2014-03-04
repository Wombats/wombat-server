package main

import (
    "fmt"
    "net/http"
    "html/template"
    "encoding/json"
    "time"
    "io/ioutil"
    "os"
    "path/filepath"
    "github.com/gorilla/mux"
)

type SiteData struct {
    Root string
}

var (
    apiroot string = "/api"
    ctx SiteData = SiteData{Root: "localhost"}
    tpls = template.Must(template.ParseFiles("tpls/login.html"))
    fileroot string = "files"
    username string = "apexskier"
)

func main() {
    fmt.Println("Starting server on port 8080.")
    r := mux.NewRouter()
    r.HandleFunc("/login", getLogin).Methods("GET")
    r.HandleFunc("/login", postLogin).Methods("POST")

    // Static files
    http.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("static"))))

    // API
    r.HandleFunc(apiroot + "/", handleApiRoot).Methods("GET")
    r.HandleFunc(apiroot + "/create/{path:.*}", jsonResponse(handleApiCreate)).Methods("POST")
    r.HandleFunc(apiroot + "/move", jsonResponse(handleApiMove)).Methods("POST")
    r.HandleFunc(apiroot + "/delete/{path:.*}", jsonResponse(handleApiRemove)).Methods("POST")
    r.HandleFunc(apiroot + "/modify/{path:.*}", handleApiModify).Methods("POST")
    r.HandleFunc(apiroot + "/download/{path:.*}", handleApiDownload).Methods("GET")
    r.HandleFunc(apiroot + "/list/{path:.*}", handleApiList).Methods("GET")
    r.HandleFunc(apiroot + "/tree/{path:.*}", handleApiTree).Methods("GET")

    http.Handle("/", r)
    http.ListenAndServe(":8080", nil)
}

type JsonString map[string]interface{}

func (r JsonString) String() (s string) {
    b, err := json.Marshal(r)
    if err != nil {
        s = ""
        return
    }
    s = string(b)
    return
}

type handler func(rw http.ResponseWriter, req *http.Request)

func jsonResponse(Decored handler) handler {
    return func(rw http.ResponseWriter, req *http.Request) {
        var (
            status string = "success"
            reason string
        )
        defer func() {
            rw.Header().Set("Content-Type", "application/json")
            if r := recover(); r != nil {
                status = "fail"
                reason = r.(string)
            }
            fmt.Fprint(rw, JsonString{"status": status, "reason": reason})
        }()
        Decored(rw, req)
    }
}

func getLogin(rw http.ResponseWriter, req *http.Request) {
    err := tpls.ExecuteTemplate(rw, "login.html", ctx)
    if err != nil {
        http.Error(rw, err.Error(), http.StatusInternalServerError)
    }
}

func postLogin(rw http.ResponseWriter, req *http.Request) {
    rw.Header().Set("Content-Type", "application/json")
    fmt.Fprint(rw, JsonString{"status": "success", "time": time.Now().Format(time.ANSIC)})
    return
}

func handleApiRoot(rw http.ResponseWriter, req *http.Request) {
    rw.Header().Set("Content-Type", "application/json")
    var status = "active"
    defer fmt.Fprint(rw, JsonString{
            "status": status,
            "time": time.Now().Format(time.ANSIC),
            "username": username})
    if username == "" {
        status = "unauthenticated"
    }
    return
}

func handleApiCreate(rw http.ResponseWriter, req *http.Request) {
    var (
        vars = mux.Vars(req)
        path = fileroot + "/" + username + "/" + vars["path"]
    )

    // TODO: Sanitize path, so users can't write to places they shouldn't
    if _, err := os.Stat(path); os.IsNotExist(err) {
        if req.Body == nil {
            panic("No request body provided.")
        }
        body, err := ioutil.ReadAll(req.Body)
        defer req.Body.Close()
        if err != nil {
            panic(err.Error())
        }

        if err = os.MkdirAll(filepath.Dir(path), 0740); err != nil {
            panic(err.Error())
        }
        if err = ioutil.WriteFile(path, body, 0740); err != nil {
            panic(err.Error())
        }
    } else {
        panic("File exists.")
    }
}

func handleApiMove(rw http.ResponseWriter, req *http.Request) {
    var data map[string]interface{}
    if req.Body == nil {
        panic("No request body.")
    }
    body, err := ioutil.ReadAll(req.Body)
    defer req.Body.Close()

    if err = json.Unmarshal(body, &data); err != nil {
        panic(err.Error())
    }
    src, oks := data["src"].(string)
    dst, okd := data["dst"].(string)
    if !oks || !okd {
        panic("Invalid json.")
    }

    path := fileroot + "/" + username + "/" + src
    dstpath := fileroot + "/" + username + "/" + dst

    if _, err = os.Stat(path); err != nil {
        panic(err.Error())
    }
    if _, err = os.Stat(dstpath); !os.IsNotExist(err) {
        panic("Overwriting destination file.")
    }
    if err = os.MkdirAll(filepath.Dir(dstpath), 0740); err != nil {
        panic(err.Error())
    }
    if err = os.Rename(path, dstpath); err != nil {
        panic(err.Error())
    }
}

func handleApiRemove(rw http.ResponseWriter, req *http.Request) {
    var path = fileroot + "/" + username + "/" + mux.Vars(req)["path"]
    if err := os.Remove(path); err != nil {
        panic(err.Error())
    }
}

func handleApiModify(rw http.ResponseWriter, req *http.Request) {
    var (
        vars = mux.Vars(req)
        status string = "success"
        reason string = ""
        path = fileroot + "/" + username + "/" + vars["path"]
    )

    // TODO: Sanitize path, so users can't write to places they shouldn't
    if _, err := os.Stat(path); err == nil {
        if req.Body == nil {
            return
        }
        body, err := ioutil.ReadAll(req.Body)
        req.Body.Close()

        err = ioutil.WriteFile(path, body, 0740)
        if err != nil {
            reason = err.Error()
            status = "fail"
        }
    } else {
        status = "fail"
        reason = err.Error()
    }
    rw.Header().Set("Content-Type", "application/json")
    fmt.Fprint(rw, JsonString{"status": status, "reason": reason})
    return
}

func handleApiDownload(rw http.ResponseWriter, req *http.Request) {
    var (
        vars = mux.Vars(req)
        path = fileroot + "/" + username + "/" + vars["path"]
    )

    // TODO: Sanitize path, so users can't write to places they shouldn't
    if _, err := os.Stat(path); os.IsNotExist(err) {
        rw.WriteHeader(http.StatusNotFound)
        return
    } else {
        body, err := ioutil.ReadFile(path)
        if err != nil {
            rw.WriteHeader(http.StatusInternalServerError)
            return
        }
        _, err = rw.Write(body)
        if err != nil {
            rw.WriteHeader(http.StatusInternalServerError)
            return
        }
        return
    }
}

func scanDir(root string, recurse bool) (items []JsonString, err error) {
    type finfo struct {
        name string
        t string
        items []JsonString
    }
    var files []os.FileInfo

    files, err = ioutil.ReadDir(root)
    if err != nil {
        return nil, err
    }
    for _, file := range files {
        fstruct := finfo{name: file.Name()}
        if file.IsDir() {
            fstruct.t = "d"
            if recurse {
                fstruct.items, err = scanDir(filepath.Join(root, fstruct.name), recurse)
                if err != nil {
                    return nil, err
                }
            }
        } else {
            fstruct.t = "f"
        }
        if recurse {
            items = append(items, JsonString{"name": fstruct.name, "t": fstruct.t, "items": fstruct.items})
        } else {
            items = append(items, JsonString{"name": fstruct.name, "t": fstruct.t})
        }
    }
    return items, nil
}

func handleApiList(rw http.ResponseWriter, req *http.Request) {
    var (
        vars = mux.Vars(req)
        status string = "success"
        reason string = ""
        items []JsonString
        path = fileroot + "/" + username + "/" + vars["path"]
    )

    if fi, err := os.Stat(path); err == nil {
        if fi.Mode().IsDir() {
            items, err = scanDir(path, false)
            if err != nil {
                status = "fail"
                reason = err.Error()
            }
        } else {
            status = "fail"
            reason = "Not a directory."
        }
    } else {
        status = "fail"
        reason = err.Error()
    }
    rw.Header().Set("Content-Type", "application/json")
    fmt.Fprint(rw, JsonString{"status": status, "reason": reason, "items": items})
    return
}

func handleApiTree(rw http.ResponseWriter, req *http.Request) {
    var (
        vars = mux.Vars(req)
        status string = "success"
        reason string = ""
        items []JsonString
        path = fileroot + "/" + username + "/" + vars["path"]
    )

    if fi, err := os.Stat(path); err == nil {
        if fi.Mode().IsDir() {
            items, err = scanDir(path, true)
            if err != nil {
                status = "fail"
                reason = err.Error()
            }
        } else {
            status = "fail"
            reason = "Not a directory."
        }
    } else {
        status = "fail"
        reason = err.Error()
    }
    rw.Header().Set("Content-Type", "application/json")
    fmt.Fprint(rw, JsonString{"status": status, "reason": reason, "items": items})
    return
}
