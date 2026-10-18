-- customers.passport was dropped; this comment must not create a field.
CREATE TABLE customers (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  ssn VARCHAR(11),
  card_number VARCHAR(19),
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT now(),
  UNIQUE (email, ssn),
  CONSTRAINT fk_other FOREIGN KEY (id) REFERENCES other (id)
);
ALTER TABLE customers ADD COLUMN health_notes TEXT;
