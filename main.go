package main

import (
	"archive/zip"
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"servers/database"
	"strconv"
	"strings"
	"sync"
	"time"

	"servers/model"

	"gopkg.in/yaml.v2"
)

type ClientInfo struct {
	Connection net.Conn
	Platform   string
}

type Server struct {
	mu             sync.Mutex
	clients        map[string]ClientInfo
	telnetSessions map[net.Conn]chan string
	results        map[string]string // 用于存储结果
	globalVars     map[string]string // 新增，用于存储全局变量
	globalVarsFile string            // 全局变量文件路径

	db           *database.Database
	techniqueMap map[string]string // 新增，用于临时存储客户端地址与ATT&CK技术标签的关系

	clientPaths map[string]string
	taskIDs     map[string]int // 用于存储客户端IP和任务ID的映射
}

func main() {
	// 初始化 MySQL 数据库连接
	// database, err := NewDatabase("root:123456789@tcp(127.0.0.1:3307)/dbname")
	// 初始化 MySQL 数据库连接
	db, err := database.NewDatabase("root:123456789@tcp(127.0.0.1:3307)/attack_results")

	if err != nil {
		fmt.Println("Error connecting to database:", err)
		os.Exit(1)
	}
	defer db.DB.Close()

	server := &Server{
		clients:        make(map[string]ClientInfo),
		telnetSessions: make(map[net.Conn]chan string),
		results:        make(map[string]string),
		globalVars:     make(map[string]string), // 初始化全局变量
		globalVarsFile: "globalVar.yaml",
		db:             db,
		techniqueMap:   make(map[string]string),
		clientPaths:    make(map[string]string), // 每次新建一个map 都要初始化操作
		taskIDs:        make(map[string]int),
	}

	err = server.loadGlobalVars()
	if err != nil {
		fmt.Println("Error loading global variables:", err)
		os.Exit(1)
	}

	defer func() {
		err := server.saveGlobalVars()
		if err != nil {
			fmt.Println("Error saving global variables:", err)
		}
	}()
	// 上面都是准备工作有关于，全局变量的加载和保存

	cert, err := tls.LoadX509KeyPair("ca/cert.pem", "ca/key.pem")
	if err != nil {
		fmt.Println("Error loading certificate:", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	listener, err := tls.Listen("tcp", ":8081", tlsConfig)
	if err != nil {
		fmt.Println("Error starting server:", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Println("TLS Server is listening on port 8081")

	go server.handleConnections(listener)
	go server.handleResults()
	go server.startFileServer()

	telnetListener, err := net.Listen("tcp", ":9090")
	if err != nil {
		fmt.Println("Error starting Telnet listener:", err)
		os.Exit(1)
	}
	defer telnetListener.Close()
	fmt.Println("Telnet server is listening on port 9090")

	go func() {
		for {
			conn, err := telnetListener.Accept()
			if err != nil {
				fmt.Println("Error accepting Telnet connection:", err)
				continue
			}
			go server.handleTelnetConnection(conn)
		}
	}()

	http.HandleFunc("/clients", server.listClientsHTTP)
	http.HandleFunc("/techniques", server.listSupportedTechniquesHTTP)
	http.HandleFunc("/send", server.sendYamlFileHTTP)
	// http.HandleFunc("/download", server.downloadYamlFileHTTP) // 新增下载接口
	http.HandleFunc("/downloadTechnique", server.downloadTechniqueFilesHTTP)
	http.HandleFunc("/disconnect", server.disconnectClientHTTP)
	http.HandleFunc("/downloadClient", server.downloadClientFileHTTP)
	http.HandleFunc("/task/details", server.getTaskDetailsHTTP)
	http.HandleFunc("/task/delete", server.deleteTaskHTTP)

	// 设备管理接口
	http.HandleFunc("/devices", server.handleDeviceManagement)

	httpServer := &http.Server{
		Addr:      ":8082",
		TLSConfig: tlsConfig,
	}

	fmt.Println("HTTPS Server is listening on port 8082")
	err = httpServer.ListenAndServeTLS("", "")
	if err != nil {
		fmt.Println("Error starting HTTPS server:", err)
	}
}

func (s *Server) deleteTaskHTTP(w http.ResponseWriter, r *http.Request) {
	taskIDStr := r.URL.Query().Get("task_id")
	if taskIDStr == "" {
		http.Error(w, "Task ID must be specified", http.StatusBadRequest)
		return
	}

	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		http.Error(w, "Invalid Task ID", http.StatusBadRequest)
		return
	}

	err = s.db.DeleteTask(taskID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error deleting task: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Task with ID %d deleted successfully", taskID)
}

func (s *Server) getTaskDetailsHTTP(w http.ResponseWriter, r *http.Request) {
	taskIDStr := r.URL.Query().Get("task_id")
	if taskIDStr == "" {
		http.Error(w, "Task ID must be specified", http.StatusBadRequest)
		return
	}

	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		http.Error(w, "Invalid Task ID", http.StatusBadRequest)
		return
	}

	task, err := s.db.GetTaskByID(taskID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error retrieving task details: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

// 断开特定客户端的连接
func (s *Server) disconnectClientHTTP(w http.ResponseWriter, r *http.Request) {
	clientAddress := r.URL.Query().Get("client")
	if clientAddress == "" {
		http.Error(w, "Client address must be specified", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	clientInfo, ok := s.clients[clientAddress]
	if ok {
		// 断开连接
		err := clientInfo.Connection.Close()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error disconnecting client: %v", err), http.StatusInternalServerError)
		} else {
			delete(s.clients, clientAddress) // 从客户端列表中移除
			fmt.Fprintf(w, "Client %s disconnected successfully\n", clientAddress)
		}
	} else {
		http.Error(w, "Client not found", http.StatusNotFound)
	}
	s.mu.Unlock()
}

func (s *Server) handleConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("Client connected:", conn.RemoteAddr().String())

	reader := bufio.NewReader(conn)
	platform, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading platform:", err)
		return
	}
	platform = strings.TrimSpace(platform)

	s.mu.Lock()
	s.clients[conn.RemoteAddr().String()] = ClientInfo{
		Connection: conn,
		Platform:   platform,
	}
	s.mu.Unlock()

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading message:", err)
			return
		}
		fmt.Printf("Received message from %s: %s", conn.RemoteAddr().String(), message)

		s.BroadcastToTelnet(fmt.Sprintf("Message from %s: %s", conn.RemoteAddr().String(), message))
	}
}

func (s *Server) handleResults() {
	listener, err := net.Listen("tcp", ":9091")
	if err != nil {
		fmt.Println("Error starting result listener:", err)
		return
	}
	defer listener.Close()
	fmt.Println("Result listener is listening on port 9091")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting result connection:", err)
			continue
		}
		go s.handleResultConnection(conn)
	}
}
func (s *Server) handleResultConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	var resultBuilder strings.Builder
	var status string

	for {
		result, err := reader.ReadString('\n')
		if err != nil {
			if err.Error() == "EOF" {
				fmt.Println("Reached EOF while reading result")
				break
			}
			fmt.Println("Error reading result:", err)
			return
		}

		if strings.TrimSpace(result) == "EOF" {
			fmt.Println("Received EOF from result reader")
			break
		}

		resultBuilder.WriteString(result)
	}

	finalResult := resultBuilder.String()
	fmt.Printf("\nReceived result: %s\n", finalResult)

	firstLine := strings.Split(finalResult, "\n")[0]

	if strings.Contains(firstLine, "SUCCESS") {
		status = "success"
	} else if strings.Contains(firstLine, "ERROR") {
		status = "failure"
	} else {
		status = "unknown"
	}

	clientIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		fmt.Println("Error parsing client address:", err)
		return
	}

	s.mu.Lock()
	attackTechnique, ok := s.techniqueMap[clientIP]
	if !ok {
		fmt.Println("Error: No attack technique found for client:", clientIP)
		attackTechnique = "Unknown" // 默认值，防止数据库字段为空
	}

	taskID, ok := s.taskIDs[clientIP]
	if !ok {
		fmt.Println("Error: No task ID found for client:", clientIP)
		s.mu.Unlock()
		return
	}

	delete(s.techniqueMap, clientIP)
	delete(s.taskIDs, clientIP)
	s.results[clientIP] = finalResult
	s.mu.Unlock()

	fmt.Printf("Attack Technique for client %s: %s\n", clientIP, attackTechnique)

	// 更新任务状态为完成
	err = s.db.CompleteTask(taskID, finalResult, status)
	if err != nil {
		fmt.Println("Error completing task in database:", err)
	} else {
		fmt.Printf("Task completed with ID: %d\n", taskID)
	}

	s.BroadcastToTelnet(finalResult)
}

func (s *Server) handleTelnetConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Fprintln(conn, "    _     _______ _______    ____   _  __ ")
	fmt.Fprintln(conn, "   / \\   (_______|_______)  / ___| | |/ / ")
	fmt.Fprintln(conn, "  / _ \\      _      _      | |     | ' /  ")
	fmt.Fprintln(conn, " / ___ \\    | |    | |     | |___  | . \\  ")
	fmt.Fprintln(conn, "/_/   \\_\\   |_|    |_|      \\____| |_|\\_\\ ")
	fmt.Fprintln(conn, "")
	fmt.Fprintln(conn, "Welcome to ATT&CK Tools v1.0.0")
	fmt.Fprintln(conn, "")
	fmt.Fprintln(conn, "Available commands:")
	fmt.Fprintln(conn, "  list      - List all connected clients")
	fmt.Fprintln(conn, "  listfile  - List all available YAML files")
	fmt.Fprintln(conn, "  send <client_address> <yaml_file> - Send a YAML file to a specific client")
	fmt.Fprintln(conn, "")
	fmt.Fprintln(conn, "Welcome to the server. Enter command:")

	responseChan := make(chan string)
	s.mu.Lock()
	s.telnetSessions[conn] = responseChan
	s.mu.Unlock()

	go func() {
		for msg := range responseChan {
			fmt.Fprintln(conn, msg)
		}
	}()

	scanner := bufio.NewScanner(conn)

	for {
		fmt.Fprint(conn, "> ")
		if !scanner.Scan() {
			break
		}
		command := scanner.Text()
		fmt.Printf("Received command: %s\n", command)

		command = strings.TrimSpace(command)
		if command == "list" {
			s.listClients(conn)
		} else if command == "listfile" {
			s.listSupportedTechniques(conn)
		} else if strings.HasPrefix(command, "send") {
			parts := strings.Split(command, " ")
			if len(parts) != 4 {
				fmt.Fprintln(conn, "Usage: send <client_address> <yaml_file> <device_name>")
				continue
			}
			clientAddress := parts[1]
			yamlFile := parts[2]
			deviceName := parts[3]
			s.sendYamlFile(conn, clientAddress, yamlFile, deviceName)
		} else {
			fmt.Fprintln(conn, "Unknown command")
		}
	}
	s.mu.Lock()
	delete(s.telnetSessions, conn)
	s.mu.Unlock()
	close(responseChan)
}

func (s *Server) listClients(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintln(conn, "Connected clients:")
	for address, clientInfo := range s.clients {
		fmt.Fprintf(conn, "Address: %s, Platform: %s\n", address, clientInfo.Platform)
	}
}

func (s *Server) listSupportedTechniques(conn net.Conn) {
	const yamlDir = "./yaml_files"

	err := filepath.Walk(yamlDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintln(conn, "Error accessing path:", err)
			return err
		}

		// 检查文件是否是 YAML 文件
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".yaml") {
			relativePath, _ := filepath.Rel(yamlDir, path)
			fmt.Fprintln(conn, relativePath)
		}
		return nil
	})

	if err != nil {
		fmt.Fprintln(conn, "Error reading directory:", err)
	}
}

func (s *Server) sendYamlFile(conn net.Conn, clientAddress string, yamlFile string, deviceName string) {
	s.mu.Lock()
	clientInfo, ok := s.clients[clientAddress]
	s.mu.Unlock()

	if !ok {
		fmt.Fprintln(conn, "Client not found")
		return
	}

	// 基于提供的相对路径构造 YAML 文件的完整路径
	fullPath := filepath.Join("./yaml_files", yamlFile)

	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		fmt.Fprintln(conn, "Error reading YAML file:", err)
		return
	}

	if len(data) == 0 {
		fmt.Fprintln(conn, "YAML file is empty, not sending to client")
		return
	}

	// 从文件名中提取 ATT&CK 技术标签和文件所在路径
	attackTechnique := strings.Split(filepath.Base(yamlFile), "_")[0]
	clientIP, _, _ := net.SplitHostPort(clientAddress)
	path := strings.Join(strings.Split(yamlFile, "/")[:3], "/")

	var attackTech model.AttackTechnique
	err = yaml.Unmarshal(data, &attackTech)
	if err != nil {
		fmt.Fprintln(conn, "Error parsing YAML file:", err)
		return
	}
	taskDescription := attackTech.AtomicTests[0].Description // 提取description

	// 创建任务并获取 taskID
	// taskID, err := s.db.InsertTask(clientIP, attackTechnique)
	taskID, err := s.db.InsertTask(clientIP, attackTechnique, deviceName, taskDescription)
	if err != nil {
		fmt.Fprintln(conn, "Failed to create task in the database:", err)
		return
	}

	// 将技术标签存储到 techniqueMap 中
	s.mu.Lock()
	s.techniqueMap[clientIP] = attackTechnique
	s.clientPaths[clientIP] = path
	s.taskIDs[clientIP] = taskID
	s.mu.Unlock()

	// 这部分是把参数替代成为我们所需要的具体参数
	yamlContent := string(data)
	for key, value := range s.globalVars {
		yamlContent = strings.ReplaceAll(yamlContent, "#{"+key+"}", value)
	}

	// 发送 YAML 内容到客户端
	fmt.Fprintf(conn, "Sending YAML file %s to client %s\n", yamlFile, clientAddress)
	_, err = clientInfo.Connection.Write([]byte("yaml\n"))
	if err != nil {
		fmt.Fprintln(conn, "Error sending YAML header:", err)
		return
	}
	_, err = clientInfo.Connection.Write([]byte(yamlContent)) // 修改后发送过去
	if err != nil {
		fmt.Fprintln(conn, "Error sending YAML data:", err)
		return
	}
	_, err = clientInfo.Connection.Write([]byte("\nEOF\n"))
	if err != nil {
		fmt.Fprintln(conn, "Error sending EOF:", err)
		return
	}

	// 更新任务状态为 "sent"
	err = s.db.UpdateTaskStatus(taskID, "pending")
	if err != nil {
		fmt.Fprintln(conn, "Error updating task status:", err)
	}
}

// func (s *Server) listSupportedTechniques(conn net.Conn) {
// 	const yamlDir = "./yaml_files"
// 	files, err := ioutil.ReadDir(yamlDir)
// 	if err != nil {
// 		fmt.Fprintln(conn, "Error reading directory:", err)
// 		return
// 	}
// 	fmt.Fprintln(conn, "Supported ATT&CK techniques (YAML files):")
// 	for _, file := range files {
// 		if !file.IsDir() && strings.HasSuffix(file.Name(), ".yaml") {
// 			fmt.Fprintln(conn, file.Name())
// 		}
// 	}
// }
// func (s *Server) sendYamlFile(conn net.Conn, clientAddress string, yamlFile string) {
// 	s.mu.Lock()
// 	clientInfo, ok := s.clients[clientAddress]
// 	s.mu.Unlock()
// 	if !ok {
// 		fmt.Fprintln(conn, "Client not found")
// 		return
// 	}
// 	const baseDir = "./yaml_files/"
// 	fullPath := baseDir + yamlFile
// 	data, err := ioutil.ReadFile(fullPath)
// 	if err != nil {
// 		fmt.Fprintln(conn, "Error reading YAML file:", err)
// 		return
// 	}
// 	if len(data) == 0 {
// 		fmt.Fprintln(conn, "YAML file is empty, not sending to client")
// 		return
// 	}
// 	// 提取 ATT&CK 技术标签（假设文件名格式为 Txxxx_something.yaml）
// 	attackTechnique := strings.Split(yamlFile, "_")[0]
// 	clientIP, _, _ := net.SplitHostPort(clientAddress)
// 	// fmt.Printf("attackTechnique: %v\n", attackTechnique)
// 	// fmt.Printf("clientAddress: %v\n", clientIP)
// 	// 将技术标签存储到 techniqueMap 中，关联到客户端地址
// 	s.mu.Lock()
// 	s.techniqueMap[clientIP] = attackTechnique
// 	s.mu.Unlock()
// 	// 这部分是把参数替代成为我们所需要的具体参数
// 	yamlContent := string(data)
// 	// fmt.Printf("Original yamlContent: %v\n", yamlContent)
// 	for key, value := range s.globalVars {
// 		// fmt.Printf("Replacing #{%s} with %s\n", key, value)
// 		yamlContent = strings.ReplaceAll(yamlContent, "#{"+key+"}", value)
// 	}
// 	// fmt.Printf("Modified yamlContent: %v\n", yamlContent)
// 	//// 	fmt.Fprintf(conn, "Sending YAML file %s to client %s\n", yamlFile, clientAddress)
// 	_, err = clientInfo.Connection.Write([]byte("yaml\n"))
// 	if err != nil {
// 		fmt.Fprintln(conn, "Error sending YAML header:", err)
// 		return
// 	}
// 	_, err = clientInfo.Connection.Write([]byte(yamlContent)) // 修改这里把修改后的发送过去
// 	if err != nil {
// 		fmt.Fprintln(conn, "Error sending YAML data:", err)
// 		return
// 	}
// 	_, err = clientInfo.Connection.Write([]byte("\nEOF\n"))
// 	if err != nil {
// 		fmt.Fprintln(conn, "Error sending EOF:", err)
// 		return
// 	}
// }

// BroadcastToTelnet 将消息广播给所有 Telnet 会话
func (s *Server) BroadcastToTelnet(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.telnetSessions {
		ch <- message
	}
}

// HTTP处理函数：列出客户端
func (s *Server) listClientsHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintln(w, "Connected clients:")
	for address, clientInfo := range s.clients {
		fmt.Fprintf(w, "Address: %s, Platform: %s\n", address, clientInfo.Platform)
	}
}

// HTTP处理函数：列出支持的技术
func (s *Server) listSupportedTechniquesHTTP(w http.ResponseWriter, r *http.Request) {
	const yamlDir = "./yaml_files"

	err := filepath.Walk(yamlDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 只显示YAML文件
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".yaml") {
			relativePath, _ := filepath.Rel(yamlDir, path)
			fmt.Fprintln(w, relativePath)
		}
		return nil
	})

	if err != nil {
		http.Error(w, "Error reading directory: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// HTTP处理函数：下载YAML文件
func (s *Server) downloadTechniqueFilesHTTP(w http.ResponseWriter, r *http.Request) {
	technique := r.URL.Query().Get("technique")
	if technique == "" {
		http.Error(w, "Technique must be specified", http.StatusBadRequest)
		return
	}

	// 获取完整路径
	techniquePath := filepath.Join("./yaml_files", technique)

	// 创建ZIP文件的完整路径
	zipFileName := fmt.Sprintf("%s.zip", filepath.Base(technique))
	zipFilePath := filepath.Join(filepath.Dir(techniquePath), zipFileName)

	// 检查并创建目录（如果不存在）
	if err := os.MkdirAll(filepath.Dir(zipFilePath), 0755); err != nil {
		http.Error(w, fmt.Sprintf("Error creating directories: %v", err), http.StatusInternalServerError)
		return
	}

	// 创建ZIP文件
	zipFile, err := os.Create(zipFilePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating ZIP file: %v", err), http.StatusInternalServerError)
		return
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)

	// 遍历并添加文件到ZIP
	err = filepath.Walk(techniquePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(techniquePath, path)
			if err != nil {
				return err
			}

			zipEntry, err := zipWriter.Create(relPath)
			if err != nil {
				return err
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(zipEntry, file)
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		zipWriter.Close()
		http.Error(w, fmt.Sprintf("Error adding files to ZIP: %v", err), http.StatusInternalServerError)
		return
	}

	// 关闭 ZIP 写入器以完成写入
	if err := zipWriter.Close(); err != nil {
		http.Error(w, fmt.Sprintf("Error closing ZIP writer: %v", err), http.StatusInternalServerError)
		return
	}

	// 将ZIP文件发送回客户端
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipFileName))
	w.Header().Set("Content-Type", "application/zip")

	zipFile.Seek(0, 0)
	_, err = io.Copy(w, zipFile)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error sending ZIP file: %v", err), http.StatusInternalServerError)
		return
	}

	// 删除临时的ZIP文件
	os.Remove(zipFilePath)
}

// HTTP处理函数：发送YAML文件并返回结果
func (s *Server) sendYamlFileHTTP(w http.ResponseWriter, r *http.Request) {
	clientAddress := r.URL.Query().Get("client")
	filesParam := r.URL.Query().Get("files")
	deviceName := r.URL.Query().Get("device")

	clientIP, _, err := net.SplitHostPort(clientAddress)
	if err != nil {
		http.Error(w, "Invalid client address", http.StatusBadRequest)
		fmt.Printf("DEBUG: Invalid client address: %s\n", clientAddress)
		return
	}

	// 验证设备名称是否存在于数据库中
	device, err := s.db.GetDeviceByName(deviceName)
	if err != nil {
		if err.Error() == "device not found" {
			http.Error(w, "Device not found", http.StatusBadRequest)
			fmt.Printf("DEBUG: Device not found: %s\n", deviceName)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		fmt.Printf("DEBUG: Database error: %v\n", err)
		return
	}

	// 将多个文件路径用逗号分隔，并拆分成一个文件列表
	yamlFiles := strings.Split(filesParam, ",")
	fmt.Printf("DEBUG: Parsed YAML files: %v\n", yamlFiles)

	for _, yamlFile := range yamlFiles {
		yamlFile = strings.TrimSpace(yamlFile)
		lastSlashIndex := strings.LastIndex(yamlFile, "/")
		var path string
		if lastSlashIndex != -1 {
			path = yamlFile[:lastSlashIndex]
			fmt.Println("Path:", path)
		} else {
			fmt.Println("Invalid file path:", yamlFile)
		}
		fullPath := filepath.Join("./yaml_files", yamlFile)
		fmt.Printf("DEBUG: Full path for YAML file: %s\n", fullPath)

		data, err := ioutil.ReadFile(fullPath)
		if err != nil {
			fmt.Fprintf(w, "Error reading YAML file %s: %s\n", yamlFile, err.Error())
			return
		}

		if len(data) == 0 {
			fmt.Fprintf(w, "YAML file %s is empty\n", yamlFile)
			return
		}

		yamlContent := string(data)
		for key, value := range s.globalVars {
			yamlContent = strings.ReplaceAll(yamlContent, "#{"+key+"}", value)
		}

		// 解析 YAML 文件以提取任务描述
		var attackTech model.AttackTechnique
		err = yaml.Unmarshal([]byte(yamlContent), &attackTech)
		if err != nil {
			fmt.Fprintf(w, "Error parsing YAML file %s: %s\n", yamlFile, err.Error())
			return
		}
		taskDescription := attackTech.AtomicTests[0].Description
		attackTechnique := attackTech.AttackTechnique

		// 在数据库中插入新任务记录，包含设备名称和任务描述
		taskID, err := s.db.InsertTask(clientIP, attackTechnique, device.Name, taskDescription)
		if err != nil {
			fmt.Fprintf(w, "Error creating task in database for %s: %s\n", yamlFile, err.Error())
			return
		}
		fmt.Printf("DEBUG: Created task with ID: %d\n", taskID)

		s.mu.Lock()
		s.clientPaths[clientIP] = path
		clientInfo, ok := s.clients[clientAddress]
		s.taskIDs[clientIP] = taskID
		s.mu.Unlock()

		if !ok {
			fmt.Fprintf(w, "Client not found for %s\n", yamlFile)
			return
		}

		_, err = clientInfo.Connection.Write([]byte("yaml\n"))
		if err != nil {
			fmt.Fprintf(w, "Error sending YAML header for %s: %s\n", yamlFile, err.Error())
			return
		}
		_, err = clientInfo.Connection.Write([]byte(yamlContent))
		if err != nil {
			fmt.Fprintf(w, "Error sending YAML data for %s: %s\n", yamlFile, err.Error())
			return
		}
		_, err = clientInfo.Connection.Write([]byte("\nEOF\n"))
		if err != nil {
			fmt.Fprintf(w, "Error sending EOF for %s: %s\n", yamlFile, err.Error())
			return
		}

		err = s.db.UpdateTaskStatus(taskID, "running")
		if err != nil {
			fmt.Fprintf(w, "Error updating task status for %s: %s\n", yamlFile, err.Error())
			return
		}

		// 等待任务结果并处理
		result := s.waitForTaskResult(clientIP, taskID, yamlFile)
		if result == "" {
			fmt.Fprintf(w, "Failed to receive result for %s\n", yamlFile)
			return
		}

		fmt.Fprintf(w, "Received result from client for %s:\n%s\n", yamlFile, result)

	}
	fmt.Fprintln(w, "All tasks have been sent and executed.")
}

func (s *Server) waitForTaskResult(clientIP string, taskID int, yamlFile string) string {
	timeout := time.After(30 * time.Second)
	tick := time.Tick(500 * time.Millisecond)

	// var result string
	for {
		select {
		case <-timeout:
			fmt.Printf("DEBUG: Timeout waiting for client result for %s\n", yamlFile)
			return ""
		case <-tick:
			s.mu.Lock()
			result, ok := s.results[clientIP]
			if ok {
				delete(s.results, clientIP)
			}
			s.mu.Unlock()
			if ok {
				err := s.db.CompleteTask(taskID, result, "completed")
				if err != nil {
					fmt.Printf("DEBUG: Error completing task in database for %s: %s\n", yamlFile, err.Error())
					return ""
				}
				return result
			}
		}
	}
}

func (s *Server) loadGlobalVars() error {
	data, err := ioutil.ReadFile(s.globalVarsFile)
	// for key, value := range s.globalVars {
	// 	fmt.Printf("Global variable %s = %s\n", key, value)
	// }
	// fmt.Printf("data: %v\n", data)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &s.globalVars)
}

// Save global variables to YAML file
func (s *Server) saveGlobalVars() error {
	data, err := yaml.Marshal(&s.globalVars)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.globalVarsFile, data, 0644)
}

func (s *Server) startFileServer() {
	listener, err := net.Listen("tcp", ":8083")
	if err != nil {
		fmt.Println("Error starting file server:", err)
		return
	}
	defer listener.Close()
	fmt.Println("File server is listening on port 8083")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting file connection:", err)
			continue
		}
		go s.handleFileConnection(conn) // 这里通过 Server 实例调用 handleFileConnection
	}
}

func (s *Server) handleFileConnection(conn net.Conn) {
	defer conn.Close()

	// 接收文件名
	reader := bufio.NewReader(conn)
	fileName, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading file name:", err)
		return
	}
	fileName = strings.TrimSpace(fileName)

	// 接收文件大小
	fileSizeStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading file size:", err)
		return
	}
	fileSizeStr = strings.TrimSpace(fileSizeStr)
	fileSize, err := strconv.ParseInt(fileSizeStr, 10, 64)
	if err != nil {
		fmt.Println("Error parsing file size:", err)
		return
	}

	// 创建接收文件
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// 接收文件内容
	n, err := io.CopyN(file, conn, fileSize)
	if err != nil {
		fmt.Println("Error receiving file:", err)
		return
	}

	fmt.Printf("Received file %s (%d bytes)\n", fileName, n)

	// 获取客户端 IP
	clientIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		fmt.Println("Error parsing client address:", err)
		return
	}

	// 根据 IP 获取路径
	s.mu.Lock()
	targetDir, ok := s.clientPaths[clientIP]
	s.mu.Unlock()
	fmt.Printf("targetDir: %v\n", targetDir)
	if ok {
		targetPath := "./yaml_files/" + targetDir + "/" + fileName
		// os.MkdirAll(targetDir, 0755) // 确保目标目录存在
		os.Rename(fileName, targetPath)
		fmt.Printf("Moved file %s to %s\n", fileName, targetPath)
	} else {
		fmt.Println("No path found for client:", clientIP)
	}
}

// curl -v -k --noproxy "*" -OJ "https://10.50.1.207:8082/downloadClient?os=windows"

// 下载客户端的接口
func (s *Server) downloadClientFileHTTP(w http.ResponseWriter, r *http.Request) {
	osType := r.URL.Query().Get("os")
	if osType == "" {
		http.Error(w, "OS type must be specified", http.StatusBadRequest)
		return
	}

	var filePath string
	if osType == "windows" {
		filePath = "./clients/client_windows.exe"
	} else if osType == "linux" {
		filePath = "./clients/client_linux.exe"
	} else {
		http.Error(w, "Unsupported OS type", http.StatusBadRequest)
		return
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("Error getting file info:", err)
		http.Error(w, "Could not get file info", http.StatusInternalServerError)
		return
	}

	// 设置HTTP头
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileInfo.Name()))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// 发送文件内容
	_, err = io.Copy(w, file)
	if err != nil {
		fmt.Println("Error sending file:", err)
		http.Error(w, "Error sending file", http.StatusInternalServerError)
		return
	}

	fmt.Println("File sent successfully:", filePath)
}

func (s *Server) handleDeviceManagement(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var device database.Device
		err := json.NewDecoder(r.Body).Decode(&device)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}
		deviceID, err := s.db.InsertDevice(&device)
		if err != nil {
			http.Error(w, "Failed to create device: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "Device created with ID: %d", deviceID)

	case "GET":
		devices, err := s.db.GetDevices()
		if err != nil {
			http.Error(w, "Failed to retrieve devices: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(devices)

	case "PUT":
		var device database.Device
		err := json.NewDecoder(r.Body).Decode(&device)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}
		err = s.db.UpdateDevice(&device)
		if err != nil {
			http.Error(w, "Failed to update device: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Device updated")

	case "DELETE":
		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			http.Error(w, "Device ID is required", http.StatusBadRequest)
			return
		}
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "Invalid Device ID", http.StatusBadRequest)
			return
		}
		err = s.db.DeleteDevice(id)
		if err != nil {
			http.Error(w, "Failed to delete device: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Device deleted")
	}
}
