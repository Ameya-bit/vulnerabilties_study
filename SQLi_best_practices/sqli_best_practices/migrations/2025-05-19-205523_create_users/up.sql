CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL
);

CREATE OR REPLACE FUNCTION create_user(uname VARCHAR, em VARCHAR)
RETURNS users AS $$
DECLARE
    new_user users;
BEGIN
    INSERT INTO users(username, email)
    VALUES (uname, em)
    RETURNING * INTO new_user;
    RETURN new_user;
END;
$$ LANGUAGE plpgsql;