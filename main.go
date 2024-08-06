package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
)

type ClientInfo struct {
	Connection net.Conn
	Platform   string
}

type Server struct {
	mu             sync.Mutex
	clients        map[string]ClientInfo
	telnetSessions map[net.Conn]chan string
}

func main() {
	server := &Server{
		clients:        make(map[string]ClientInfo),
		telnetSessions: make(map[net.Conn]chan string),
	}

	var err error
	listener, err := net.Listen("tcp", ":8081")
	if err != nil {
		fmt.Println("Error starting server:", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Println("Server is listening on port 8081")

	go server.handleConnections(listener)

	go server.handleResults()

	// 启动Telnet服务，允许远程用户连接
	telnetListener, err := net.Listen("tcp", ":9090")
	if err != nil {
		fmt.Println("Error starting Telnet listener:", err)
		os.Exit(1)
	}
	defer telnetListener.Close()
	fmt.Println("Telnet server is listening on port 9090")

	for {
		conn, err := telnetListener.Accept()
		if err != nil {
			fmt.Println("Error accepting Telnet connection:", err)
			continue
		}
		go server.handleTelnetConnection(conn)
	}
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

		// 将消息广播给所有 Telnet 会话
		s.broadcastToTelnet(fmt.Sprintf("Message from %s: %s", conn.RemoteAddr().String(), message))
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

	// 将结果广播给所有 Telnet 会话
	s.broadcastToTelnet(finalResult)
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
	// fmt.Fprintln(conn, "Enter command:")

	responseChan := make(chan string)
	s.mu.Lock()
	s.telnetSessions[conn] = responseChan
	s.mu.Unlock()

	go func() {
		for msg := range responseChan {
			fmt.Fprintln(conn, msg)
		}
	}()

	fmt.Fprintln(conn, "Welcome to the server. Enter command:")
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
		} else if command == "listfile" { // 新命令处理
			s.listSupportedTechniques(conn)
		} else if strings.HasPrefix(command, "send") {
			parts := strings.Split(command, " ")
			if len(parts) != 3 {
				fmt.Fprintln(conn, "Usage: send <client_address> <yaml_file>")
				continue
			}
			clientAddress := parts[1]
			yamlFile := parts[2]
			s.sendYamlFile(conn, clientAddress, yamlFile)
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

func (s *Server) sendYamlFile(conn net.Conn, clientAddress string, yamlFile string) {
	s.mu.Lock()
	clientInfo, ok := s.clients[clientAddress]
	s.mu.Unlock()

	if !ok {
		fmt.Fprintln(conn, "Client not found")
		return
	}

	const baseDir = "./yaml_files/"
	fullPath := baseDir + yamlFile

	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		fmt.Fprintln(conn, "Error reading YAML file:", err)
		return
	}

	if len(data) == 0 {
		fmt.Fprintln(conn, "YAML file is empty, not sending to client")
		return
	}

	fmt.Fprintf(conn, "Sending YAML file %s to client %s\n", yamlFile, clientAddress)
	_, err = clientInfo.Connection.Write([]byte("yaml\n"))
	if err != nil {
		fmt.Fprintln(conn, "Error sending YAML header:", err)
		return
	}
	_, err = clientInfo.Connection.Write(data)
	if err != nil {
		fmt.Fprintln(conn, "Error sending YAML data:", err)
		return
	}
	_, err = clientInfo.Connection.Write([]byte("\nEOF\n"))
	if err != nil {
		fmt.Fprintln(conn, "Error sending EOF:", err)
		return
	}
}

// 将消息广播给所有 Telnet 会话
func (s *Server) broadcastToTelnet(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.telnetSessions {
		ch <- message
	}
}

// 支持新的命令
func (s *Server) listSupportedTechniques(conn net.Conn) {
	const yamlDir = "./yaml_files" // 更新为指向新的子目录
	files, err := ioutil.ReadDir(yamlDir)
	if err != nil {
		fmt.Fprintln(conn, "Error reading directory:", err)
		return
	}

	fmt.Fprintln(conn, "Supported ATT&CK techniques (YAML files):")
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".yaml") {
			fmt.Fprintln(conn, file.Name())
		}
	}
}
