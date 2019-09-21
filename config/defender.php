<?php return [

	/**
	 * Power of the Bcrypt - any number between 4 and 31 -> hash is better if number is hihter
	 */
	'cost' => 12,

	/**
	 * Session preferences.
	 */
	'session' => [
		'type'  => 'native', // Session type: native, database, ...
        'expiration' => 3600, // Time of user inactivity before the session is finished
		'key' => 'DEFENDER' // Key stored in session with user data
	],

	/**
	 * Login block on failed attempt.
	 * Name of the key - number of failed attempts.
	 * Value of the key - block time.
	 * IMPORTANT!!! In DB must exist fields last_attempt and failed_attempt + uncomment lines below.
	 */
	'rate_limits' => [
		3  => 30,  // after 3 failed attempts, wait 30 seconds between each next attempt
		5  => 60,  // after 5 failed attempts, wait 1 minute between each next attempt
		10 => 300  // after 5 failed attempts, wait 10 minutes between each next attempt
	],

	/**
	 * Logging settings.
	 */
	'logging' => [
		'auth' => [ // Authentication
			'success' => LOG::INFO,
			'failed' => LOG::WARNING,
		],
		'access' => [ // User access
			'success' => LOG::INFO,
			'failed' => LOG::WARNING,
		]
	],

	/**
	 * ORM model names which used to get user info.
	 * @tutorial Models must contains relation fields user и role.
	 */
	'user_model' => 'User', // Users
	'role_model' => 'Role', // Roles

	/**
	 * Map between fields from code and fields from DB.
	 */
	'uattr'   => [ // User model
		'id' => 'id', // User ID
		'username' => 'username', // User name
		'password' => 'password', // Password
		'active' => 'active', // User is active
		//'last_login' => 'last_login', // (optional) Date and time of the last user logon
		//'logins' => 'logins', // (optional) User logon number
		//'last_attempt' => 'last_attempt', // (optional) Date and time of the last success logon attempt
        //'failed_attempts' => 'failed_attempts', //  (optional) Date and time of the last failed logon attempt
		'roles' => 'roles' // Link to the Role model of the user
	],
	'rattr' => [ // Role model
		'id' => 'id', // Role ID
		'rolename' => 'rolename', // Role name
		'rolecode' => 'rolecode', // Role code
		'roleact' => 'roleact', // Actions allowed to the role
		'users' => 'users' // Link to the User model
	],

];

/*
 * DB scripts
 *
 *
	'scripts' => [
		'users' => "
			CREATE TABLE users (
				uid int(10) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'Идентификатор записи пользователя.',
				username varchar(32) NOT NULL COMMENT 'Уникальный логин пользователя.',
				password varchar(255) NOT NULL COMMENT 'MD5 хэш пароля пользователя.',
				active tinyint(1) NOT NULL DEFAULT 0 COMMENT 'Признак того, что учетная запись пользователя активна в данный момент.',
				last_login datetime NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT 'Дата и время последнего входа пользователя в систему.',
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
	],
*/
