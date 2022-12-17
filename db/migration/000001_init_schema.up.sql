CREATE TABLE  access(
                        userid INT identity(1,1) PRIMARY KEY,
                        fullname VARCHAR(255) NOT NULL,
                        username VARCHAR(50) NOT NULL,
                        password VARCHAR(150) NOT NULL
);

--123456
INSERT INTO access(fullname, username, password) VALUES('Usuario Aforo255 1', 'aforo255','$2a$10$LVvqRveAcL/zVLerfnjIdOcUhoEay5ukLBj..Bih8a531fkqjUx8u');
INSERT INTO access(fullname, username, password) VALUES('Usuario Aforo255 2', 'aforo2','$2a$10$LVvqRveAcL/zVLerfnjIdOcUhoEay5ukLBj..Bih8a531fkqjUx8u');
INSERT INTO access(fullname, username, password) VALUES('Usuario Aforo255 3', 'aforo3','$2a$10$LVvqRveAcL/zVLerfnjIdOcUhoEay5ukLBj..Bih8a531fkqjUx8u');