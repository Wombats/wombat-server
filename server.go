package main

import (
    "fmt"
    "errors"
    "net/http"
    "html/template"
    "encoding/json"
    "encoding/gob"
    "time"
    "io/ioutil"
    "os"
    "path/filepath"
    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "github.com/gorilla/context"
)

type SiteData struct {
    Root string
}
type UserData struct {
    username string
    hash string
    email string
}
type Authorizer struct {
    users map[string]UserData
    filepath string
}
func NewAuthorizer(fpath string) Authorizer {
    var a Authorizer
    if _, err := os.Stat(fpath); err != nil {
        panic(err.Error())
    }
    f, err := os.Open(fpath)
    defer f.Close()
    if err != nil {
        panic(err.Error())
    }
    dec := gob.NewDecoder(f)
    dec.Decode(&a.users)
    if a.users == nil {
        a.users = make(map[string]UserData)
    }
    a.filepath = fpath
    fmt.Println(a)
    return a
}
func (a Authorizer) Save(u UserData) error {
    if _, ok := a.users[u.username]; ok {
        return errors.New("User already exists.")
    }
    a.users[u.username] = u

    f, err := os.Create("data/auth")
    defer f.Close()
    if err != nil {
        fmt.Println("No auth file found.")
        panic("No file.")
    }
    enc := gob.NewEncoder(f)
    fmt.Println(a.users)
    err = enc.Encode(a.users)
    return nil
}
func (a Authorizer) Login(u string, p string) error {
    err := a.Save(UserData{u, u + p, ""})
    if err != nil {
        return err
    }
    if user, ok := a.users[u]; !ok {
        return errors.New("User not found.")
    } else {
        hash := u + p
        if user.hash != hash {
            return errors.New("Password doesn't match.")
        }
    }
    return nil
}

var (
    apiroot string = "/api"
    ctx SiteData = SiteData{Root: "localhost"}
    tpls = template.Must(template.ParseFiles("tpls/login.html"))
    fileroot string = "files"
    cookiejar = sessions.NewCookieStore([]byte("wombat-secret-key"))
    authstore = sessions.NewFilesystemStore("data/auth.gob", []byte("wombat-secret-key-2"))
    aaa Authorizer = NewAuthorizer("data/auth")
)

func main() {
    fmt.Println("Starting server on port 8080.")
    r := mux.NewRouter()

    gob.Register(&UserData{})

    // Pages
    r.HandleFunc("/login", getLogin).Methods("GET")
    r.HandleFunc("/login", jsonResponse(postLogin)).Methods("POST")

    // Static files
    http.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("static"))))

    // API
    r.HandleFunc(apiroot, addSlash);
    r.HandleFunc(apiroot + "/",                     authorize(handleApiRoot)).Methods("GET")
    r.HandleFunc(apiroot + "/create/{path:.*}",     authorize(jsonResponse(handleApiCreate))).Methods("POST")
    r.HandleFunc(apiroot + "/move",                 authorize(jsonResponse(handleApiMove))).Methods("POST")
    r.HandleFunc(apiroot + "/delete/{path:.*}",     authorize(jsonResponse(handleApiRemove))).Methods("POST")
    r.HandleFunc(apiroot + "/modify/{path:.*}",     authorize(jsonResponse(handleApiModify))).Methods("POST")
    r.HandleFunc(apiroot + "/download/{path:.*}",   authorize(handleApiDownload)).Methods("GET")
    r.HandleFunc(apiroot + "/list/{path:.*}",       authorize(handleApiList)).Methods("GET")
    r.HandleFunc(apiroot + "/tree/{path:.*}",       authorize(handleApiTree)).Methods("GET")

    r.StrictSlash(false)

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

func authorize(Decored handler) handler {
    return func(rw http.ResponseWriter, req *http.Request) {
        session, err := cookiejar.Get(req, "auth")
        panicIfErr(err);
        username := session.Values["username"]
        if username == nil {
            http.Error(rw, "You must login to do that.", http.StatusUnauthorized)
            return
        }
        context.Set(req, "username", username)
        Decored(rw, req)
    }
}

func panicIfErr(e error) {
    if e != nil {
        panic(e.Error())
    }
}

func getDstPath(req *http.Request) string {
    return fileroot + "/" + context.Get(req, "username").(string) + "/" + mux.Vars(req)["path"]
}

func addSlash(rw http.ResponseWriter, req *http.Request) {
    http.Redirect(rw, req, req.URL.Path + "/", http.StatusMovedPermanently)
}

func getLogin(rw http.ResponseWriter, req *http.Request) {
    err := tpls.ExecuteTemplate(rw, "login.html", ctx)
    if err != nil {
        http.Error(rw, err.Error(), http.StatusInternalServerError)
    }
}

func postLogin(rw http.ResponseWriter, req *http.Request) {
    panicIfErr(req.ParseForm())
    username := req.PostFormValue("username")
    password := req.PostFormValue("password")
    panicIfErr(aaa.Login(username, password))

    session, _ := cookiejar.Get(req, "auth")
    session.Values["username"] = username

    // panicIfErr(session.Save(req, rw))
    http.Redirect(rw, req, "/api", http.StatusAccepted)
    return
}

func handleApiRoot(rw http.ResponseWriter, req *http.Request) {
    rw.Header().Set("Content-Type", "application/json")
    var status = "active"
    defer fmt.Fprint(rw, JsonString{
            "status": status,
            "time": time.Now().Format(time.ANSIC),
            "username": context.Get(req, "username")})
    return
}

func handleApiCreate(rw http.ResponseWriter, req *http.Request) {
    var path = getDstPath(req)

    // TODO: Sanitize path, so users can't write to places they shouldn't
    if _, err := os.Stat(path); os.IsNotExist(err) {
        if req.Body == nil {
            panic("No request body provided.")
        }
        body, err := ioutil.ReadAll(req.Body)
        defer req.Body.Close()
        panicIfErr(err);

        panicIfErr(os.MkdirAll(filepath.Dir(path), 0740))
        panicIfErr(ioutil.WriteFile(path, body, 0740))
    } else {
        panic("File exists.")
    }
}

func handleApiMove(rw http.ResponseWriter, req *http.Request) {
    var (
        data map[string]interface{}
        username string = context.Get(req, "username").(string)
    )

    if req.Body == nil {
        panic("No request body.")
    }
    body, err := ioutil.ReadAll(req.Body)
    defer req.Body.Close()

    panicIfErr(json.Unmarshal(body, &data))
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
    panicIfErr(os.MkdirAll(filepath.Dir(dstpath), 0740))
    panicIfErr(os.Rename(path, dstpath))
}

func handleApiRemove(rw http.ResponseWriter, req *http.Request) {
    var path = getDstPath(req)
    panicIfErr(os.Remove(path))
}

func handleApiModify(rw http.ResponseWriter, req *http.Request) {
    var path = getDstPath(req)
    // TODO: Sanitize path, so users can't write to places they shouldn't

    if _, err := os.Stat(path); err != nil { panic(err.Error()) }

    body, err := ioutil.ReadAll(req.Body)
    defer req.Body.Close()
    if err != nil { panic(err.Error()) }

    panicIfErr(ioutil.WriteFile(path, body, 0740))
}

func handleApiDownload(rw http.ResponseWriter, req *http.Request) {
    var path = getDstPath(req)

    // TODO: Sanitize path, so users can't write to places they shouldn't
    if _, err := os.Stat(path); os.IsNotExist(err) {
        http.Error(rw, "404 file not found.", http.StatusNotFound)
        return
    } else {
        body, err := ioutil.ReadFile(path)
        if err != nil {
            http.Error(rw, err.Error(), http.StatusInternalServerError)
            return
        }
        _, err = rw.Write(body)
        if err != nil {
            http.Error(rw, err.Error(), http.StatusInternalServerError)
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
func handleWalkDir(rw http.ResponseWriter, req *http.Request, recurse bool) {
    var (
        status string = "success"
        reason string
        items []JsonString
        path = getDstPath(req)
    )
    defer func() {
        if r := recover(); r != nil {
            status = "fail"
            reason = r.(string)
        }
        rw.Header().Set("Content-Type", "application/json")
        fmt.Fprint(rw, JsonString{"status": status, "reason": reason, "items": items})
    }()

    if fi, err := os.Stat(path); err != nil {
        panic(err.Error())
    } else {
        if !fi.Mode().IsDir() { panic("Not a directory.") }
    }

    items, err := scanDir(path, recurse);
    panicIfErr(err)
}

func handleApiList(rw http.ResponseWriter, req *http.Request) { handleWalkDir(rw, req, false) }

func handleApiTree(rw http.ResponseWriter, req *http.Request) { handleWalkDir(rw, req, true) }
