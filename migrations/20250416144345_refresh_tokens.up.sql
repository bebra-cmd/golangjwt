CREATE TABLE IF NOT EXISTS refresh_tokens (
jti VARCHAR,
token BYTEA,
exp_date VARCHAR  
);
CREATE INDEX idx_jti ON refresh_tokens(jti); --btree