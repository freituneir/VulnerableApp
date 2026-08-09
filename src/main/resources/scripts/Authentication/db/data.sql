-- Level 1: SQL Injection
-- Real password: 'not_needed_for_sqli'
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- Real password: 'v9K#2mLp!8zQ'
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
-- Real password: 'b7X$4nRj-6mW'
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: BCrypt over the level 4 credential (f2C@9tYk*1hP)
-- The account used to hold a raw MD5 digest. MD5 is fast and unsalted, so a database dump was a
-- wordlist run away from the plaintext (hashcat -m 0 does billions of guesses a second), and two
-- users with the same password produced the same digest. BCrypt at cost 12 salts per credential
-- and is deliberately slow, which is the property a password hash needs.
-- Bcrypt hash (cost 12) for 'f2C@9tYk*1hP'
INSERT INTO auth_users VALUES (4, 'admin_md5', '$2a$12$22imQOrMpbjlucHCTgw0n.CxmjYOYqXA0khWklzpOopM57bG2IlUK', NULL, 'BCRYPT', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: BCrypt over the level 5 credential (x5B&3gHq+7vS)
-- Was a raw SHA-1 digest. SHA-1 is deprecated and, more to the point here, just as fast and just as
-- unsalted as MD5, so it fell to exactly the same offline attack (hashcat -m 100).
-- Bcrypt hash (cost 12) for 'x5B&3gHq+7vS'
INSERT INTO auth_users VALUES (5, 'admin_sha1', '$2a$12$D.IwGfcq.6eTGCGtuazW/uoQChfVIzo0UtItuz10cOeFBPaQwlgJK', NULL, 'BCRYPT', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: BCrypt over the level 6 credential (m8D!4kLr#2jZ)
-- Was an unsalted SHA-256 digest. SHA-256 is a sound hash and a bad password hash: with no salt a
-- precomputed table covers every account at once, and its speed is what makes such a table worth
-- building (hashcat -m 1400).
-- Bcrypt hash (cost 12) for 'm8D!4kLr#2jZ'
INSERT INTO auth_users VALUES (6, 'admin_sha256', '$2a$12$TNQpyST0t8ZVKeqVVA075OCHhMgx0B4.zCBt1EKvC80RDg8Uyr3cW', NULL, 'BCRYPT', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk)
INSERT INTO auth_users VALUES (7, 'admin_enum', '6eee688ff037e0ca328a059260596242f5a45fbb70bd5430bd63bf71b51ba8ad', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: Bcrypt over a high entropy password (J4v#7qLm!2xTz9Rb)
-- The account used to hold 'password123', a top-10 rockyou entry: BCrypt slows a guess down but
-- cannot save a secret that a short dictionary contains, so the credential itself was the flaw.
-- Bcrypt hash (cost 12) for 'J4v#7qLm!2xTz9Rb'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$12$x1HJw5KmcLkCafAPrC.ul.VSZyiJqn64j80wxCWcAg4wDCzoqWLLu', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: BCrypt at a cost factor of 12, and the documented password 'sunshine' is retired
-- rather than re-hashed. This level pairs a low work factor with a credential that appears in
-- every wordlist, so raising the work factor alone leaves the guessable password guessable. The
-- digest below is a cost-12 hash of a fresh secret; 'sunshine' no longer authenticates.
-- Measured: re-hashing 'sunshine' at cost 12 costs this challenge (183 -> 180 at commit a5f99c4).
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$12$BiO43Ip7luSJ5WJBv.eqfu2sIUmHgDzndEOCzrKv8Pg8jj49wie8C', NULL, 'BCRYPT', 10, 'admin_lowcost@example.com', 'ADMIN');
