CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL
);

-- Add index for faster API key lookups
CREATE INDEX idx_api_key ON users (api_key); 