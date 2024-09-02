package database

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

type Database struct {
	DB *sql.DB
}

// 初始化数据库连接
func NewDatabase(dsn string) (*Database, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %v", err)
	}
	return &Database{DB: db}, nil
}

// 插入新任务到数据库

func (d *Database) InsertTask(clientIP, attackTechnique, deviceName, taskDescription string) (int, error) {
	res, err := d.DB.Exec("INSERT INTO tasks (client_ip, attack_technique, device_name, task_description, status) VALUES (?, ?, ?, ?, ?)",
		clientIP, attackTechnique, deviceName, taskDescription, "creating")
	if err != nil {
		return 0, fmt.Errorf("error inserting task into database: %v", err)
	}
	lastID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("error fetching last insert ID: %v", err)
	}
	return int(lastID), nil
}

// 更新任务状态和执行状态
func (d *Database) UpdateTaskStatus(taskID int, status string) error {
	_, err := d.DB.Exec("UPDATE tasks SET status = ? WHERE id = ?", status, taskID)
	if err != nil {
		return fmt.Errorf("error updating task status in database: %v", err)
	}
	return nil
}

// 更新任务结果和完成时间
func (d *Database) CompleteTask(taskID int, result, exeStatus string) error {
	_, err := d.DB.Exec("UPDATE tasks SET result = ?, exe_status = ?, status = 'completed', completed_at = NOW() WHERE id = ?",
		result, exeStatus, taskID)
	if err != nil {
		return fmt.Errorf("error completing task: %v", err)
	}
	return nil
}

// 查询特定 ATT&CK 技术标签和状态下的所有任务
func (d *Database) GetTasksByTechnique(tagName, status string) ([]Task, error) {
	rows, err := d.DB.Query(`
        SELECT id, client_ip, attack_technique, status, exe_status, result, created_at, started_at, completed_at, error_message
        FROM tasks
        WHERE attack_technique = ? AND status = ?`, tagName, status)
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var task Task
		err := rows.Scan(&task.ID, &task.ClientIP, &task.AttackTechnique, &task.Status, &task.ExeStatus, &task.Result,
			&task.CreatedAt, &task.StartedAt, &task.CompletedAt, &task.ErrorMessage)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %v", err)
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}

// GetTaskByID retrieves a task by its ID from the database.
func (d *Database) GetTaskByID(taskID int) (*Task, error) {
	row := d.DB.QueryRow(`
        SELECT id, client_ip, attack_technique, status, exe_status, result, created_at, 
        IFNULL(started_at, '') AS started_at, 
        IFNULL(completed_at, '') AS completed_at, 
        IFNULL(error_message, '') AS error_message, 
        device_name, task_description
        FROM tasks
        WHERE id = ?`, taskID)

	var task Task
	err := row.Scan(
		&task.ID,
		&task.ClientIP,
		&task.AttackTechnique,
		&task.Status,
		&task.ExeStatus,
		&task.Result,
		&task.CreatedAt,
		&task.StartedAt,
		&task.CompletedAt,
		&task.ErrorMessage,
		&task.DeviceName,
		&task.TaskDescription,
	)
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}

	return &task, nil
}

// DeleteTask deletes a task by its ID from the database.
func (d *Database) DeleteTask(taskID int) error {
	_, err := d.DB.Exec("DELETE FROM tasks WHERE id = ?", taskID)
	if err != nil {
		return fmt.Errorf("error deleting task from database: %v", err)
	}
	return nil
}

// 插入新设备信息
func (d *Database) InsertDevice(device *Device) (int, error) {
	res, err := d.DB.Exec("INSERT INTO devices (name, ip_address, identifier, manufacturer, device_type) VALUES (?, ?, ?, ?, ?)",
		device.Name, device.IPAddress, device.Identifier, device.Manufacturer, device.DeviceType)
	if err != nil {
		return 0, fmt.Errorf("error inserting device into database: %v", err)
	}
	lastID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("error fetching last insert ID: %v", err)
	}
	return int(lastID), nil
}

// 更新设备信息
func (d *Database) UpdateDevice(device *Device) error {
	_, err := d.DB.Exec("UPDATE devices SET name=?, ip_address=?, identifier=?, manufacturer=?, device_type=? WHERE id=?",
		device.Name, device.IPAddress, device.Identifier, device.Manufacturer, device.DeviceType, device.ID)
	if err != nil {
		return fmt.Errorf("error updating device in database: %v", err)
	}
	return nil
}

func (d *Database) DeleteDevice(id int) error {
	_, err := d.DB.Exec("DELETE FROM devices WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("error deleting device from database: %v", err)
	}
	return nil
}

// 查询所有设备信息
func (d *Database) GetDevices() ([]Device, error) {
	rows, err := d.DB.Query("SELECT id, name, ip_address, identifier, manufacturer, device_type, created_at FROM devices")
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		err := rows.Scan(&device.ID, &device.Name, &device.IPAddress, &device.Identifier, &device.Manufacturer, &device.DeviceType, &device.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %v", err)
		}
		devices = append(devices, device)
	}
	return devices, nil
}

// 查询设备是否存在
func (d *Database) GetDeviceByName(deviceName string) (*Device, error) {
	var device Device
	err := d.DB.QueryRow("SELECT id, name, ip_address, identifier, manufacturer, device_type, created_at FROM devices WHERE name = ?", deviceName).
		Scan(&device.ID, &device.Name, &device.IPAddress, &device.Identifier, &device.Manufacturer, &device.DeviceType, &device.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("device not found")
		}
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	return &device, nil
}

// 定义 Task 结构体用于查询任务
type Task struct {
	ID              int    `json:"id"`
	ClientIP        string `json:"client_ip"`
	AttackTechnique string `json:"attack_technique"`
	Status          string `json:"status"`
	ExeStatus       string `json:"exe_status"`
	Result          string `json:"result"`
	CreatedAt       string `json:"created_at"`
	StartedAt       string `json:"started_at"`
	CompletedAt     string `json:"completed_at"`
	ErrorMessage    string `json:"error_message"`
	DeviceName      string `json:"device_name"`
	TaskDescription string `json:"task_description"`
}

// Device represents the device information stored in the database
type Device struct {
	ID           int    `json:"ID"`
	Name         string `json:"name"`
	IPAddress    string `json:"ip_address"`
	Identifier   string `json:"identifier"`
	Manufacturer string `json:"manufacturer"`
	DeviceType   string `json:"device_type"`
	CreatedAt    string `json:"created_at"`
}
