INSERT INTO users (username, password, roles)
  values ('user',
    '$2a$10$JpaoqL/Idi5nhPbkY6LsGuYNobSXRcR16p9hL./pLVYNsLmb5Mite',
    'ROLE_USER');

--     password is 'user'

INSERT INTO users (username, password, roles)
  values ('admin',
    '$2a$10$Twr2HqGXP1eNK8ld3FNc.OhvGUSEmS1QrFEjyJpue.1d3mBAjMksG',
    'ROLE_USER,ROLE_ADMIN');

--     password is 'admin'