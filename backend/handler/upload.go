package handler

import (
	"awesomeProject1/backend/model"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"path/filepath"
	"sync"
)

func UploadHandler(c *gin.Context) {

	model.AttackFiles = sync.Map{}
	model.TcpFiles = sync.Map{}

	if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "表单解析失败"})
		return
	}

	if type1Files, ok := c.Request.MultipartForm.File["attack"]; ok {
		for _, fileHeader := range type1Files {
			attackFile := &model.UploadedFile{
				FieldName: "attack",
				FileName:  filepath.Base(fileHeader.Filename),
				FileSize:  fileHeader.Size,
			}
			model.AttackFiles.Store(fileHeader.Filename, attackFile)
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "attack log may have some trouble"})
	}
	fmt.Println(&model.AttackFiles)

	if type2Files, ok := c.Request.MultipartForm.File["tcp"]; ok {
		for _, fileHeader := range type2Files {
			tcpFile := &model.UploadedFile{
				FieldName: "tcp",
				FileName:  filepath.Base(fileHeader.Filename),
				FileSize:  fileHeader.Size,
			}
			model.TcpFiles.Store(fileHeader.Filename, tcpFile)
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "tcp log may have some trouble"})
	}
	fmt.Println(&model.TcpFiles)
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}
