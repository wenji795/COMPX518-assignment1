DROP TABLE IF EXISTS verification_users;


CREATE TABLE verification_users (
                       id INT AUTO_INCREMENT PRIMARY KEY,
                       username VARCHAR(255) NOT NULL UNIQUE,
                       password VARCHAR(255) NOT NULL
);
