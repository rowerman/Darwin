CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name TEXT, price DECIMAL);
INSERT INTO products (name, price) VALUES ('Widget', 9.99), ('Gadget', 19.99), ('Flag Holder', 29.99)
  ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT);
INSERT INTO users (username, password) VALUES ('admin', 'supersecret_admin_pass_12345')
  ON CONFLICT DO NOTHING;
