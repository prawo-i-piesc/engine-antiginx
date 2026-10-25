-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
-- Fixture data, not a real database
CREATE TABLE `users` (`id` int NOT NULL, `email` varchar(255), `password_hash` varchar(255));
INSERT INTO `users` VALUES (1,'admin@shop.example','fixture-not-a-real-hash');
