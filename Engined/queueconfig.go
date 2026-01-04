package main

import "github.com/streadway/amqp"

type RabbitConfig struct {
	ConnCh       *amqp.Connection
	TaskCh       *amqp.Channel
	ErrMidConnCh chan *amqp.Error
}
