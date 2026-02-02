// example/simple.go
package main

import (
	"log"
	"time"

	"github.com/met465m/bedrock_rocket_bot/client"
	"github.com/met465m/bedrock_rocket_bot/control"
)

func main() {
	bot := client.NewClient("mc-zone.ru", 19132, "test_bot", 582)

	bot.OnJoin(func() {
		log.Println("🤖 Бот вошёл Можно начинать действия...")

		time.Sleep(2 * time.Second)
		control.SendMessage(bot.Conn, "Привет с бота!")

		time.Sleep(2 * time.Second)
		control.Jump(bot.Conn, 100, 64, 100, 45, 10)

		for {
			time.Sleep(10 * time.Second)
			log.Println("👋 Бот онлайн")
		}
	})

	log.Println("Запускаем...")
	err := bot.Launch()
	if err != nil {
		log.Fatalf("Ошибка: %v", err)
	}
}
