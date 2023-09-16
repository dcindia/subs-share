CREATE TABLE users (
    sub         TEXT PRIMARY KEY
                     UNIQUE
                     NOT NULL,
    email       TEXT UNIQUE
                     NOT NULL,
    username    TEXT UNIQUE,
    name        TEXT,
    given_name  TEXT,
    credentials TEXT
);
