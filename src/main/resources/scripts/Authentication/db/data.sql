-- Passwords are no longer written next to the rows they open. Levels 1, 2, 3 and 10 are seeded
-- as BCrypt at the application's work factor; each level's documented password still works, only
-- the stored form changed.

-- Level 1: SQL Injection
INSERT INTO auth_users VALUES (1, 'admin_sqli', '$2a$12$rqt5Gs.hJfRYDdl.PFyQ0OxsCgTf/e1biVMF.ifkbnf8TpEP574Pi', NULL, 'BCRYPT', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
INSERT INTO auth_users VALUES (2, 'admin_logs', '$2a$12$kk45a0Z7yz6AF8u1bPLjA.BpAk7Xfs4uE4p420zn.bMzAfU4DFEuu', NULL, 'BCRYPT', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
INSERT INTO auth_users VALUES (3, 'admin_plain', '$2a$12$01mjbv4Pykv6Ms3PTIl/Z.rHnM6WY4hy3FM2MwJFadLkIQGQLcIsS', NULL, 'BCRYPT', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: was an unsalted MD5 digest. MD5 is fast and collision prone, and the stored digest
-- matched no password anyone could present, so nothing is lost by re-seeding it as BCrypt.
INSERT INTO auth_users VALUES (4, 'admin_md5', '$2a$12$t/EozqklLvUSCBzSaga8mOp8.eLtWph/7cWQOdyXCsGj9lzpbJN4y', NULL, 'BCRYPT', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: was an unsalted SHA-1 digest, deprecated and just as fast to enumerate.
INSERT INTO auth_users VALUES (5, 'admin_sha1', '$2a$12$sUcV0ChFyiAOPfz/j1KAJOlj0wosGhsJ0F.uXMLyf5ckWUxuwqCRi', NULL, 'BCRYPT', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: was an unsalted SHA-256 digest. A sound hash, but fast and saltless is the wrong
-- shape for a password: equal passwords gave equal digests and rainbow tables applied.
INSERT INTO auth_users VALUES (6, 'admin_sha256', '$2a$12$syvdfhw/QpS0k6a1BTsj5.pwXtvmB.IlEn7E2glqmcGtHwVC4Rgpa', NULL, 'BCRYPT', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256. The seeded digest did not cover the salt, so the level could not be
-- logged into at all; it is now SHA-256(salt || password) as the verifier computes it.
INSERT INTO auth_users VALUES (7, 'admin_enum', '6eee688ff037e0ca328a059260596242f5a45fbb70bd5430bd63bf71b51ba8ad', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: the account held 'password123'. BCrypt does not help when the password is in every
-- wordlist, so the account is seeded with a long random one at the standard work factor.
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$12$cARQxNSFdmF5MLrDppnkBOmobk3Vd7WK9Zf9quuPPYQVDP2eN8foe', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error)
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: BCrypt at the standard work factor. A cost of 4 is a few thousand guesses a second per
-- core; the documented password is unchanged so the level still logs in.
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$12$uu01hAgWpMXeoVcdxr59T.Gge21Bx/gsA9UmefvRkwNF4NDNQTRDq', NULL, 'BCRYPT', 10, 'admin_lowcost@example.com', 'ADMIN');
