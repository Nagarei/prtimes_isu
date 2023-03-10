package main

import (
	"crypto/md5"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "net/http/pprof"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
)

var (
	db    *sqlx.DB
	store *gsm.MemcacheStore
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
	imageDir      = "../images"
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int32     `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User `db:"u"`
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User      `db:"u"`
}

var UserWithID = &sync.Map{} // map[int]*User{}
func getUserWithID(id int) User {
	userraw, ok := UserWithID.Load(id)
	if !ok {
		return User{}
	}
	user, ok := userraw.(*User)
	if !ok {
		log.Fatal("userraw.(*User) error")
		return User{}
	}
	return User{
		ID:          user.ID,
		AccountName: user.AccountName,
		Passhash:    user.Passhash,
		Authority:   user.Authority,
		DelFlg:      atomic.LoadInt32(&user.DelFlg),
		CreatedAt:   user.CreatedAt,
	}
}

type CommentList struct {
	arr   []Comment //昇順(limitは後ろから)
	count int
	mutex sync.RWMutex
}

var CommentWithPostID = &sync.Map{} // map[int]*CommentList{}

func initMemoryCache() {
	log.Print("initMemoryCache")
	log.Print("users...")
	userTmp := []User{}
	err := db.Select(&userTmp, "SELECT * FROM users")
	if err != nil {
		log.Fatal(err)
		return
	}
	UserWithID = &sync.Map{}
	for i := range userTmp {
		UserWithID.Store(userTmp[i].ID, &userTmp[i])
	}

	log.Print("comments...")
	commentTmp := []Comment{}
	err = db.Select(&commentTmp, "SELECT * FROM comments ORDER BY post_id, created_at")
	if err != nil {
		log.Fatal(err)
		return
	}
	CommentWithPostID = &sync.Map{}
	for _, c := range commentTmp {
		del := getUserWithID(c.UserID).DelFlg
		arrraw, _ := CommentWithPostID.LoadOrStore(c.PostID, &CommentList{arr: []Comment{}})
		clist, ok := arrraw.(*CommentList)
		if !ok {
			log.Fatal("arrraw.(*CommentList) error")
			return
		}
		clist.mutex.Lock()
		if del == 0 {
			clist.arr = append(clist.arr, c)
		}
		clist.count += 1
		clist.mutex.Unlock()
	}
	log.Print("done")
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient := memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func dbInitialize() {
	{
		results := []Post{}
		err := db.Select(&results, "SELECT `id`, `mime` FROM `posts` WHERE id > 10000")
		if err != nil {
			log.Fatal(err)
			return
		}
		for _, p := range results {
			ext := MimeToExt(p.Mime)
			os.Remove(imageDir + "/" + strconv.Itoa(p.ID) + "." + ext)
		}
	}

	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
	if _, err := os.Stat(imageDir); err != nil {
		// not exists
		os.Mkdir(imageDir, os.ModePerm)
		results := []Post{}
		err := db.Select(&results, "SELECT `id`, `mime`, `imgdata` FROM `posts`")
		if err != nil {
			log.Fatal(err)
			return
		}
		for _, p := range results {
			WriteFile((int64)(p.ID), p.Mime, p.Imgdata)
		}
	}

	initMemoryCache()
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
}

func digest(src string) string {
	// opensslのバージョンによっては (stdin)= というのがつくので取る
	out, err := exec.Command("/bin/bash", "-c", `printf "%s" `+escapeshellarg(src)+` | openssl dgst -sha512 | sed 's/^.*= //'`).Output()
	if err != nil {
		log.Print(err)
		return ""
	}

	return strings.TrimSuffix(string(out), "\n")
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uidraw, ok := session.Values["user_id"]
	if !ok || uidraw == nil {
		return User{}
	}
	uid, ok := uidraw.(int)
	if !ok {
		log.Print("uid is not int")
		log.Print(uidraw)
		return User{}
	}

	return getUserWithID(uid)
	//u := User{}
	// err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	// if err != nil {
	// 	return User{}
	// }

	//return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	var posts []Post

	for _, p := range results {
		if p.User.ID == 0 {
			p.User = getUserWithID(p.UserID)
		}
		if p.User.DelFlg != 0 {
			continue
		}

		arrraw, _ := CommentWithPostID.LoadOrStore(p.ID, &CommentList{arr: []Comment{}})
		clist := arrraw.(*CommentList)
		clist.mutex.RLock()
		p.CommentCount = clist.count
		var comments []Comment
		del := false
		i := len(clist.arr) - 1
		for ; i >= 0; i -= 1 {
			c := clist.arr[i]
			cu := getUserWithID(c.UserID)
			if cu.DelFlg == 1 {
				del = true
				continue
			}
			c.User = cu
			comments = append(comments, c)
			if !allComments && len(comments) >= 3 {
				break
			}
		}
		clist.mutex.RUnlock()
		if del {
			go func() {
				clist.mutex.Lock()
				defer clist.mutex.Unlock()
				i := 0
				for j := 0; j < len(clist.arr); j += 1 {
					c := clist.arr[j]
					cu := getUserWithID(c.UserID)
					if cu.DelFlg == 1 {
						continue
					}
					if i != j {
						clist.arr[i] = clist.arr[j]
					}
					i += 1
				}
				clist.arr = clist.arr[:i]
			}()
		}

		// reverse
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}
		p.Comments = comments

		p.CSRFToken = csrfToken

		posts = append(posts, p)
		if len(posts) >= postsPerPage {
			break
		}
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	var u User
	db.Get(&u, "SELECT * FROM users WHERE `id` = ?", uid)
	UserWithID.Store((int)(uid), &u)
	session.Values["user_id"] = (int)(uid)
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

var index_layout = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("index.html"),
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []Post{}

	err := db.Select(&results,
		"SELECT posts.`id`, posts.`user_id`, posts.`body`, posts.`mime`, posts.`created_at` "+
			" ,u.id as 'u.id', u.account_name as 'u.account_name', u.passhash as 'u.passhash', u.authority as 'u.authority', u.del_flg as 'u.del_flg', u.created_at as 'u.created_at'"+
			" FROM `posts` IGNORE INDEX (userid_createdat)"+
			" join users as u on u.id = posts.user_id"+
			" where u.del_flg = 0"+
			" ORDER BY posts.created_at DESC"+
			" LIMIT ?", postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}

	csrf_token := getCSRFToken(r)
	posts, err := makePosts(results, csrf_token, false)
	if err != nil {
		log.Print(err)
		return
	}
	w.Write([]byte(layoutTemplate(me, indexTemplate(posts, csrf_token, getFlash(w, r, "notice")))))
	//w.WriteHeader(http.StatusOK)

	// index_layout.Execute(w, struct {
	// 	Posts     []Post
	// 	Me        User
	// 	CSRFToken string
	// 	Flash     string
	// }{posts, me, csrf_token, getFlash(w, r, "notice")})
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := chi.URLParam(r, "accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var posts []Post
	if user.DelFlg == 0 {
		results := []Post{}
		err = db.Select(&results,
			"SELECT posts.`id`, posts.`user_id`, posts.`body`, posts.`mime`, posts.`created_at` FROM `posts`"+
				" where posts.`user_id` = ?"+
				" ORDER BY posts.created_at DESC"+
				" LIMIT ?", user.ID, postsPerPage)
		if err != nil {
			log.Print(err)
			return
		}
		for _, p := range results {
			p.User = user
		}

		posts, err = makePosts(results, getCSRFToken(r), false)
		if err != nil {
			log.Print(err)
			return
		}
	}

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		err = db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if err != nil {
			log.Print(err)
			return
		}
	}

	me := getSessionUser(r)

	// fmap := template.FuncMap{
	// 	"imageURL": imageURL,
	// }
	//
	// template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	// 	getTemplPath("layout.html"),
	// 	getTemplPath("user.html"),
	// 	getTemplPath("posts.html"),
	// 	getTemplPath("post.html"),
	// )).Execute(w, struct {
	// 	Posts          []Post
	// 	User           User
	// 	PostCount      int
	// 	CommentCount   int
	// 	CommentedCount int
	// 	Me             User
	// }{posts, user, postCount, commentCount, commentedCount, me})
	w.Write([]byte(layoutTemplate(me, strings.Join(userTemplate(posts, user, postCount, commentCount, commentedCount), ""))))
}

var getPostsTemplate = template.Must(template.New("posts.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFiles(
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	err = db.Select(&results,
		"SELECT posts.`id`, posts.`user_id`, posts.`body`, posts.`mime`, posts.`created_at`"+
			" ,u.id as 'u.id', u.account_name as 'u.account_name', u.passhash as 'u.passhash', u.authority as 'u.authority', u.del_flg as 'u.del_flg', u.created_at as 'u.created_at'"+
			" FROM `posts` ignore index (userid_createdat) "+
			" join users as u on u.id = posts.user_id"+
			" where posts.created_at <= ? AND u.del_flg = 0"+
			" ORDER BY posts.created_at DESC"+
			" LIMIT ?", t.Format(ISO8601Format), postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	//getPostsTemplate.Execute(w, posts)
	w.Write([]byte(strings.Join(postsTemplate(posts), "")))
}

var getPostsIDTemplate = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("post_id.html"),
	getTemplPath("post.html"),
))

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	err = db.Select(&results,
		"SELECT posts.`id`, posts.`user_id`, posts.`body`, posts.`mime`, posts.`created_at` "+
			" ,u.id as 'u.id', u.account_name as 'u.account_name', u.passhash as 'u.passhash', u.authority as 'u.authority', u.del_flg as 'u.del_flg', u.created_at as 'u.created_at'"+
			" FROM `posts`"+
			" join users as u on u.id = posts.user_id"+
			"  WHERE posts.`id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	w.Write([]byte(layoutTemplate(me, strings.Join(postTemplate(p), ""))))
	// getPostsIDTemplate.Execute(w, struct {
	// 	Post Post
	// 	Me   User
	// }{p, me})
}
func MimeToExt(mime string) string {
	ext := ""
	if mime == "image/jpeg" {
		ext = "jpg"
	} else if mime == "image/png" {
		ext = "png"
	} else if mime == "image/gif" {
		ext = "gif"
	}
	return ext
}
func WriteFile(pid int64, mime string, filedata []byte) {
	ext := MimeToExt(mime)
	f, err := os.Create(imageDir + "/" + strconv.FormatInt(pid, 10) + "." + ext)
	if err != nil {
		log.Print(err)
		return
	}
	defer f.Close()
	_, err = f.Write(filedata)
	if err != nil {
		log.Print(err)
		return
	}
}
func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		[]byte{},
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	//ファイル書き出し
	WriteFile(pid, mime, filedata)

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	const etag = "W/\"1c529a68d22d142834b68e93aa2a5a65\""
	if r.Header.Get("if-none-match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// post := Post{}
	// err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	// if err != nil {
	// 	log.Print(err)
	// 	return
	// }

	ext := chi.URLParam(r, "ext")
	if ext == "jpg" || ext == "png" || ext == "gif" {
		imgfile, err := os.Open(imageDir + "/" + strconv.Itoa(pid) + "." + ext)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mime := ""
		if ext == "jpg" {
			mime = "image/jpeg"
		} else if ext == "png" {
			mime = "image/png"
		} else if ext == "gif" {
			mime = "image/gif"
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Cache-Control", "max-age=604800, immutable")
		w.Header().Set("etag", etag)
		_, err = io.Copy(w, imgfile)
		if err != nil {
			log.Print(err)
			return
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	result, err := db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}
	cid, err := result.LastInsertId()
	var c Comment
	err = db.Get(&c, "SELECT * FROM comments WHERE `id` = ?", cid)
	if err != nil {
		log.Print(err)
		return
	}
	func() {
		arrraw, _ := CommentWithPostID.LoadOrStore(postID, &CommentList{arr: []Comment{}})
		clist, ok := arrraw.(*CommentList)
		if !ok {
			log.Print(err)
			return
		}
		clist.mutex.Lock()
		defer clist.mutex.Unlock()
		clist.arr = append(clist.arr, c)
		for i := len(clist.arr) - 1; i >= 1; i -= 1 { //念のため挿入ソート
			if clist.arr[i-1].CreatedAt.Before(clist.arr[i].CreatedAt) {
				break
			}
			clist.arr[i-1], clist.arr[i] = clist.arr[i], clist.arr[i-1]
		}
		clist.count += 1
	}()

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
		v, err := strconv.Atoi(id)
		if err != nil {
			continue
		}
		userraw, _ := UserWithID.Load(v)
		user := userraw.(*User)
		atomic.StoreInt32(&user.DelFlg, 1)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()
	go func() {
		time.Sleep(3 * time.Second)
		initMemoryCache()
	}()

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Get("/image/{id}.{ext}", getImage)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)

	staticServe := func(path string, mime string) func(w http.ResponseWriter, r *http.Request) {
		hash := md5.New()
		defer hash.Reset()
		hash.Write([]byte(password))
		etag := "W/\"" + hex.EncodeToString(hash.Sum(nil)) + "\""
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("if-none-match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			imgfile, err := os.Open("../public" + path)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", mime)
			w.Header().Set("Cache-Control", "max-age=604800, immutable")
			w.Header().Set("etag", etag)
			_, err = io.Copy(w, imgfile)
			if err != nil {
				log.Print(err)
				return
			}
			// f, err := os.Open("../public" + path)
			// if err != nil {
			// 	http.Error(w, "file not found", 404)
			// }
			// defer f.Close()
			// fi, err := f.Stat() // ファイルの各情報をファイル構造体から取得する
			// if err != nil {
			// 	http.Error(w, "file not found", 404)
			// }
			// http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
		}
	}
	r.Get("/css/style.css", staticServe("/css/style.css", "text/css; charset=utf-8"))
	r.Get("/img/ajax-loader.gif", staticServe("/img/ajax-loader.gif", "image/gif"))
	r.Get("/js/main.js", staticServe("/js/main.js", "text/javascript; charset=utf-8"))
	r.Get("/js/timeago.min.js", staticServe("/js/timeago.min.js", "text/javascript; charset=utf-8"))
	r.Get("/favicon.ico", staticServe("/favicon.ico", "image/vnd.microsoft.icon"))

	log.Fatal(http.ListenAndServe(":80", r))
}

func layoutTemplate(Me User, content string) string {
	res := make([]string, 0, 10)
	res = append(res, `<!DOCTYPE html>
	<html>
	  <head>
		<meta charset="utf-8">
		<title>Iscogram</title>
		<link href="/css/style.css" media="screen" rel="stylesheet" type="text/css">
	  </head>
	  <body>
		<div class="container">
		  <div class="header">
			<div class="isu-title">
			  <h1><a href="/">Iscogram</a></h1>
			</div>
			<div class="isu-header-menu">`)
	if Me.ID == 0 {
		res = append(res, `<div><a href="/login">ログイン</a></div>`)
	} else {
		res = append(res, `<div><a href="/@`, Me.AccountName, `"><span class="isu-account-name">`, Me.AccountName, `</span>さん</a></div>`)
		if Me.Authority == 1 {
			res = append(res, `<div><a href="/admin/banned">管理者用ページ</a></div>`)
		}
		res = append(res, `<div><a href="/logout">ログアウト</a></div>`)
	}
	res = append(res, `
			</div>
		  </div>`, content, `
		</div>
		<script src="/js/timeago.min.js"></script>
		<script src="/js/main.js"></script>
	  </body>
	</html>`)
	return strings.Join(res, "")
}
func indexTemplate(
	Posts []Post,
	CSRFToken string,
	Flash string) string {
	res := make([]string, 0, 100)
	res = append(res, `
	<div class="isu-submit">
	  <form method="post" action="/" enctype="multipart/form-data">
		<div class="isu-form">
		  <input type="file" name="file" value="file">
		</div>
		<div class="isu-form">
		  <textarea name="body"></textarea>
		</div>
		<div class="form-submit">
		  <input type="hidden" name="csrf_token" value="`, CSRFToken, `">
		  <input type="submit" name="submit" value="submit">
		</div>`)
	if Flash != "" {
		res = append(res, `<div id="notice-message" class="alert alert-danger">`,
			Flash,
			`</div>`)
	}
	res = append(res, `</form>
	</div>`)
	res = append(res, postsTemplate(Posts)...)
	res = append(res, `<div id="isu-post-more">
	  <button id="isu-post-more-btn">もっと見る</button>
	  <img class="isu-loading-icon" src="/img/ajax-loader.gif">
	</div>`)
	return strings.Join(res, "")
}
func userTemplate(ps []Post,
	User User,
	PostCount int,
	CommentCount int,
	CommentedCount int) []string {
	res := make([]string, 0, 100)
	res = append(res, `<div class="isu-user">
  <div><span class="isu-user-account-name">`, User.AccountName, `さん</span>のページ</div>
  <div>投稿数 <span class="isu-post-count">`, strconv.Itoa(PostCount), `</span></div>
  <div>コメント数 <span class="isu-comment-count">`, strconv.Itoa(CommentCount), `</span></div>
  <div>被コメント数 <span class="isu-commented-count">`, strconv.Itoa(CommentedCount), `</span></div>
</div>`)
	res = append(res, postsTemplate(ps)...)
	return res
}
func postsTemplate(ps []Post) []string {
	res := make([]string, 0, 100)
	for _, p := range ps {
		res = append(res, `<div class="isu-posts">`)
		res = append(res, postTemplate(p)...)
		res = append(res, `</div>`)
	}
	return res
}
func postTemplate(p Post) []string {
	res := make([]string, 0, 100)
	res = append(res, `<div class="isu-post" id="pid_`, strconv.Itoa(p.ID), `" data-created-at="`, p.CreatedAt.Format("2006-01-02T15:04:05-07:00"), `">
  <div class="isu-post-header">
    <a href="/@`, p.User.AccountName, ` " class="isu-post-account-name">`, p.User.AccountName, `</a>
    <a href="/posts/`, strconv.Itoa(p.ID), `" class="isu-post-permalink">
      <time class="timeago" datetime="`, p.CreatedAt.Format("2006-01-02T15:04:05-07:00"), `"></time>
    </a>
  </div>
  <div class="isu-post-image">
    <img src="`, imageURL(p), `" class="isu-image">
  </div>
  <div class="isu-post-text">
    <a href="/@`, p.User.AccountName, `" class="isu-post-account-name">`, p.User.AccountName, `</a>
    `, p.Body, `
  </div>
  <div class="isu-post-comment">
    <div class="isu-post-comment-count">
      comments: <b>`, strconv.Itoa(p.CommentCount), `</b>
    </div>
`)
	for _, c := range p.Comments {
		res = append(res, `
		<div class="isu-comment">
		  <a href="/@`, c.User.AccountName, `" class="isu-comment-account-name">`, c.User.AccountName, `</a>
		  <span class="isu-comment-text">`, c.Comment, `</span>
		</div>
		`)
	}
	res = append(res, `
    <div class="isu-comment-form">
      <form method="post" action="/comment">
        <input type="text" name="comment">
        <input type="hidden" name="post_id" value="`, strconv.Itoa(p.ID), `">
        <input type="hidden" name="csrf_token" value="`, p.CSRFToken, `">
        <input type="submit" name="submit" value="submit">
      </form>
    </div>
  </div>
</div>`)

	return res
}
