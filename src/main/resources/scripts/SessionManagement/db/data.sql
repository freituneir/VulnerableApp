-- Session credentials are stored as BCrypt digests. They were held in cleartext, so anyone
-- who could read this table held every account; the documented passwords are unchanged.
INSERT INTO session_users VALUES (1, 'Session', 'User', 'session_user', '$2a$12$M0zMT6XnBpVimm4iVgigt.VcGP01Uwf2r8vzQkVIJSe2WkZfscEDW', 'USER', FALSE);
INSERT INTO session_users VALUES (2, 'Session', 'Attacker', 'session_attacker', '$2a$12$yR3BLbmGxY9E0q0CTv5H4uMUISsz7BtHWgcRzUPnkhSxRHt0Eg5L.', 'USER', TRUE);
INSERT INTO session_users VALUES (3, 'Session', 'Admin', 'session_admin', '$2a$12$0tNXQ9REiOp1Fd/AKI123uz15o0bixeaEY8jC193VzGs4g3vAoVqG', 'ADMIN', FALSE);
INSERT INTO session_users VALUES (4, 'Session Rate Limiter', 'Victim', 'session_rate_limit_victim', '$2a$12$a2cRhp1u2Qdw9RzFLFYMke4FMY2LRisTa2VoG.EOv6jm/bqJ2mV6e', 'USER', FALSE);
