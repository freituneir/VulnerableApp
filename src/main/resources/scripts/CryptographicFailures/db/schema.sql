-- Table is seeded by CryptographicFailuresSeeder in vulnerability.service.cryptographicFailures

DROP TABLE IF EXISTS cryptographic_failures_vault;

CREATE TABLE cryptographic_failures_vault (
    level INT PRIMARY KEY ,
    password VARCHAR(500),
    algorithm VARCHAR(50)
);

-- Application user has full access (for functional purposes)
GRANT ALL ON cryptographic_failures_vault TO application;

-- The vault previously provisioned a standing account whose password was written here in
-- cleartext and derived from its own username, and handed it SELECT on the table holding
-- every level's credential. Nothing in the application ever authenticated as it; it existed
-- so that a reader of this file could log in and dump the vault. Hardening how the secrets
-- are stored is pointless while a published credential grants read access to the row, so the
-- account is gone. The application user retains the access it actually needs.