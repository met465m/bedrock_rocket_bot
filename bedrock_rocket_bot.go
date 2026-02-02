// minecraft_rocket_bot.go
package main

import (
	"log"
	"time"

	"minecraft_rocket_bot/config"
	"minecraft_rocket_bot/control"
	"minecraft_rocket_bot/net_control"
	"minecraft_rocket_bot/packet"
)

type Client struct {
	Conn   *net_control.Connection
	Server string
	Port   int
	Nick   string
	Protocol uint32
	OnJoinFunc func()
}

func NewClient(server string, port int, nick string, protocol uint32) *Client {
	return &Client{
		Server:   server,
		Port:     port,
		Nick:     nick,
		Protocol: protocol,
	}
}

func (c *Client) Launch() error {
	addr := c.Server + ":" + strconv.Itoa(c.Port)
	log.Printf("🚀 Запуск бота %s → %s", c.Nick, addr)

	conn, err := net_control.Dial(addr)
	if err != nil {
		return err
	}
	c.Conn = conn

	go c.listen()

	loginPkt := packet.CreateLogin(c.Nick, c.Protocol)
	if err := c.Conn.Write(loginPkt); err != nil {
		return err
	}

	log.Printf("📤 %s: Login отправлен", c.Nick)
	select {}
}

func (c *Client) listen() {
	buf := make([]byte, 2048)
	for {
		n, err := c.Conn.Read(buf)
		if err != nil {
			log.Printf("💀 Соединение разорвано: %v", err)
			return
		}

		if n > 0 {
			if buf[0] == 0x02 { // PlayStatus
				status := binary.LittleEndian.Uint32(buf[1:5])
				switch status {
				case 0:
					log.Printf("🎉 %s УСПЕШНО ЗАШЁЛ В ИГРУ!", c.Nick)
					if c.OnJoinFunc != nil {
						go c.OnJoinFunc()
					}
				case 2:
					log.Printf("❌ Несовместимый протокол. Попробуй другие версии: 594, 618, 621")
				case 3:
					log.Printf("❌ Логин отклонён сервером")
				default:
					log.Printf("ℹ️ Статус: %d", status)
				}
			}
		}
	}
}

func main() {
	bot := NewClient(
		config.DefaultServer,
		config.DefaultPort,
		config.DefaultNick,
		config.DefaultProtocol,
	)

	bot.OnJoinFunc = func() {
		log.Println("🤖 Бот вошёл. Можно управлять.")

		time.Sleep(2 * time.Second)
		control.SendMessage(bot.Conn, "Привет, я зашёл!")

		time.Sleep(2 * time.Second)
		control.Jump(bot.Conn, 100, 64, 100, 0, 0)

		for {
			time.Sleep(10 * time.Second)
			log.Println("✅ Бот онлайн")
		}
	}

	log.Println("Запускаем...")
	err := bot.Launch()
	if err != nil {
		log.Fatalf("Ошибка: %v", err)
	}
}
