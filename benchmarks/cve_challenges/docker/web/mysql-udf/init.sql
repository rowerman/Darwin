CREATE TABLE IF NOT EXISTS items (id INT PRIMARY KEY, name VARCHAR(255), price DECIMAL(10,2));
INSERT INTO items (id, name, price) VALUES (1, 'Widget', 9.99), (2, 'Gadget', 19.99), (3, 'Flag Holder', 29.99)
  ON DUPLICATE KEY UPDATE name=name;
