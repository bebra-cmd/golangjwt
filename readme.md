docker compose up
Если локально, то создать .env в корне + create database role исполнить файл миграции

SECRET_KEY - для цифровой подписи

JWTSHA512 OK
base64 OK
bcrypt in db OK
Изменение на стороне клиента? httponly cookie? Цифровая подпись? cookiehttponly OK 
Повторное использование? Каждый рефреш удаляет запись OK
JTI IN PAYLOAD+DB ОК
current ipaddr==payload.ipaddr OK
mail откуда? CONST in crypto.go

Не осилил создание внешнего пароля не тестил SMTP :( 

bcrypt +150ms на каждый запрос
ну и энкодинг/декодинг операции тоже норм тратят(ооо в релиз моде из контейнера затраты на операцию упали на 100+ms)