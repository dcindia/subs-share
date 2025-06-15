CREATE TABLE IF NOT EXISTS users (
    sub         TEXT        PRIMARY KEY
                            UNIQUE
                            NOT NULL,
    email       TEXT        UNIQUE
                            NOT NULL,
    username    TEXT        UNIQUE,
    name        TEXT,
    given_name  TEXT,
    credentials TEXT,
    fresh_login INTEGER (1) DEFAULT (1),
    hidden_channels TEXT DEFAULT ('[]') -- Comma-separated list of channel IDs
);
