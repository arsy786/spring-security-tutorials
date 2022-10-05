INSERT INTO users (username, password, enabled)
  values ('user',
    '$2a$10$XptfskLsT1l/bRTLRiiCgejHqOpgXFreUnNUa35gJdCr2v2QbVFzu',
    true);

INSERT INTO users (username, password, enabled)
  values ('admin',
    '$2a$10$zxvEq8XzYEYtNjbkRsJEbukHeRx3XS6MDXHMu8cNuNsRfZJWwswDy',
    true);

INSERT INTO authorities (username, authority)
  values ('user', 'ROLE_USER');

INSERT INTO authorities (username, authority)
  values ('admin', 'ROLE_ADMIN');

  INSERT INTO authorities (username, authority)
    values ('admin', 'ROLE_USER');