package db

type Access struct {
	UserId   int64  `json:"userid"`
	FullName string `json:"fullname"`
	Username string `json:"username"`
	Password string `json:"password"`
}
