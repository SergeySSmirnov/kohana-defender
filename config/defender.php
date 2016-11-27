<?php defined('SYSPATH') or die('No direct access allowed.');

return array(

	/**
	 * Мощность Bcrypt - любое число между 4 и 31 -> чем больше число, тем сильнее хэш.
	 */
	'cost' => 12,
		
	/**
	 * Настройки сессии. 
	 */
	'session' => array(
		'use' => TRUE, // Признак необходимости использовать сессию
		'store_user' => TRUE, // Признак необходимости использовать сессию для хранения данных текущего пользователя, в противном случае хранится только его имя
		'type'  => 'native', // native or database
		'expiration_session' => 3600, // Время жизни сессии
		'expiration_cookie' => 0 // Время жизни cookie
	),

	/**
	 * Установите в значение TRUE, чтобы установить заголовки Cache-Control & Pragma,
	 * которые позволяют предотвратить пользователю использовать кнопку назад после
	 * завершения сеанса работы с системой.
	 */
	'prevent_browser_cache' => TRUE,
		
	/**
	 * Отключает возможность аутентификации пользователя от возможности войти в систему
	 * в случае брутфорса (подбора паролей) на определенное время, определяемое в зависимости
	 * от числа неудачных попыток входа.
	 * Имя ключа - число неудачных попыток входа, его значение - период времени, на которое
	 * деактивируется учетная запись. 
	 * ВАЖНО! Для того, чтобы включить данную возможность, необходимо в таблице пользователи
	 * добавить два столбца last_attempt и failed_attempt, а в конфигурационном файле
	 * раскомментировать соответствующие строки в массиве соответствий.
	 */
	'rate_limits' => array(
		3  => 30,  // after 3 failed attempts, wait 30 seconds between each next attempt
		5  => 60,  // after 5 failed attempts, wait 1 minute between each next attempt
		10 => 300  // after 5 failed attempts, wait 10 minutes between each next attempt
	),
		
	/**
	 * Параметры ведения журнала событий.
	 * Если ведение журнала событий в определенном случае не нужно,
	 * то следует установить значение в FLASE, в противном случае
	 * необходимо назначить соответсвующую константу из LOG, например, LOG::WARNING.
	 */
	'logging' => array(
		'auth' => array( // Параметры ведения журнала событий при аутентификации пользователя
			'success' => FALSE, // При успешной аутентификации пользователя
			'filed' => FALSE, // При неудачной попытке аутентификации пользователя
		),
		'access' => array( // Параметры ведения журнала событий при проверке прав пользователей
			'success' => FALSE, // При успешном доступе к ресурсу
			'filed' => FALSE, // При неудачной попытке доступа к ресурсу
		),
	),
		
	/**
	 * Используемый движок для доступа к БД.
	 */
	'driver' => 'ORM',
	
	/**
	 * Имена таблиц данных, используемых для доступа к данным в БД.
	 * @tutorial В моделях данных должны быть определены связи user и role для того, чтобы можно было обратиться к таблице связи Роли Пользователей.
	 */
	'user_model' => 'user', // Пользователи
	'role_model' => 'role', // Роли
				
	/**
	 * Определяем соответствие столбцам таблицы.
	 */
	'uattr'   => array( // Таблица пользователи
		'id' => 'id', // id пользователя
		'username' => 'username', // Имя пользователя
		'password' => 'password', // Пароль
		'active' => 'active', // Признак того, что учетная запись активна
		'token' => 'token', // Ключ
		//'last_login' => 'last_login', // (Опция) Дата и время последнего входа пользователя в систему
		//'logins' => 'logins', // (Опция) Общее число входов пользователем в систему
		//'last_attempt' => 'last_attempt', // (Опция) Дата и время последней попытки входа пользователя в систему
		//'failed_attempts' => 'failed_attempts', // (Опция) Число безуспешных попыток входа
	),
	'rattr' => array( // Таблица роли
		'id' => 'id', // id роли 
		'rolename' => 'rolename', // Название роли
		'rolecode' => 'rolecode', // Код роли
		'roleact' => 'roleact', // Действия, допустимые для роли
	),
		
		
	/**
	 * Скрипты генерации таблиц в БД.
	 */
	'scripts' => array(
		'users' => "
			CREATE TABLE users (
				uid int(10) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'Идентификатор записи пользователя.',
				username varchar(32) NOT NULL COMMENT 'Уникальный логин пользователя.',
				password varchar(255) NOT NULL COMMENT 'MD5 хэш пароля пользователя.',
				active tinyint(1) NOT NULL DEFAULT 0 COMMENT 'Признак того, что учетная запись пользователя активна в данный момент.',
				token varchar(255) NOT NULL COMMENT 'Ключ сессии.',last_login datetime NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT 'Дата и время последнего входа пользователя в систему.',
				logins int(10) UNSIGNED NOT NULL COMMENT 'Число входов пользователя.',
				last_attempt datetime NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT 'Дата и время последней попытки входа пользователя в систему.',
				failed_attempts smallint(5) UNSIGNED NOT NULL COMMENT 'Число безуспешных попыток входа.',
				PRIMARY KEY (uid),
				UNIQUE INDEX USER_LOGIN (username),
			)
			ALTER TABLE ROLES COMMENT 'Данные о пользователях системы.';
			INSERT INTO users(uid, username, password, active) VALUES (1, 'admin', '$2a$12\$L0EIxFp5phhEotnXiHkwtOsxwMDDgU7.8K3C84g/DvqnLKKstn2C6', 1); // admin 123456; ",
		'roles' => "
			CREATE TABLE roles (
			   rid int UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'Идентификатор записи роли.',
			   name varchar(255) NOT NULL COMMENT 'Название роли.',
			   code varchar(45) NOT NULL COMMENT 'Код роли',
			   role longtext NOT NULL COMMENT 'Действия, допустимые для роли.',
			   PRIMARY KEY (rid),
			   KEY ROLE_NAME (name)
			);
			ALTER TABLE roles COMMENT 'Справочник. Содержит список ролей, которые возможны в системе.';
			INSERT INTO roles(rid, rolNazv, rolDeistviya) VALUES (1, 'Guest', 'restrict all');
			INSERT INTO roles(rid, rolNazv, rolDeistviya) VALUES (2, 'SuperAdmin', 'allow all'); ",
		'user_roles' => "
			CREATE TABLE user_roles (
			  uid int(10) UNSIGNED NOT NULL COMMENT 'Идентификатор записи пользователя.',
			  rid int(10) UNSIGNED NOT NULL COMMENT 'Идентификатор записи роли.',
			  PRIMARY KEY (uid, rid),
			)
			ALTER TABLE user_roles COMMENT = 'Данные о ролях пользователей.';
			INSERT INTO user_roles(uid, rid) VALUES (1, 2); ",
	),
		
);