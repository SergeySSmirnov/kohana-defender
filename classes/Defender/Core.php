<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * Представляет класс ядра модуля пользовательской аутентификации с использованием bcrypt
 * bcrypt рекомендуется многими для безопасного хранения паролей.
 * Больше информации смотрите на сайте: http://codahale.com/how-to-safely-store-a-password/
 * Основан на Kohana's AUTH, Fred Wu's AUTHLITE и Woody Gilk's Bonafide.
 * @package Defender
 * @copyright  (c) 2011 Wouter
 * @copyright  (c) 2011 Woody Gilk
 * @copyright  (c) 2011 Fred Wu
 * @copyright  (c) 2011 Kohana Team
 * @copyright  (c) 2010-14 RUSproj, Sergey S. Smirnov
 * @license    MIT
 */
abstract class Defender_Core {

	/**
	 * Возвращает статический экземпляр класса.
	 * @param string $name Имя создаваемого экземпляра класса.
	 * @param string $confn Имя конфигурационного файла.
	 * @param Config $config Конфигурационные данные модуля.
	 * @return Defender Созданный экземпляр класса.
	 * @throws Kohana_Exception Генерируется в том случае, если сервер не поддерживает Bcrypt.
	 */
	public static function instance($name = 'def', $confn = 'defender', $config = NULL) {
		if (CRYPT_BLOWFISH !== 1) { // Если сервер не поддерживает bcrypt, то генерируем исключение
			throw new Defender_Exception('Данный сервер не поддерживает возможность хэширования bcrypt.');
		}
		if (!isset(self::$_instances[$name])) { // Если не создан экземпляр класса
			$_config = Arr::merge(Kohana::$config->load($confn)->as_array(), $config); // Загружаем конфигурационные данные
			$class = ucfirst($confn);
			self::$_instances[$name] = new $class($name, $_config); // Создаем экземпляр класса и помещаем в массив экземпляров
		}
		return self::$_instances[$name]; // Возвращаем созданный экземпляр
	}
	/**
	 * Создаёт запись пользователя с указанными параметрами. Если пользователь с таким логином существует, то ему будут назначены лишь указанные права.
	 * @param int|string|ORM $userName Имя пользователя, которого необходимо создать.
	 * @param string $userPasswd Пароль создаваемого пользователя.
	 * @param boolean $userActive Признак что пользователь должен иметь статус "Активен".
	 * @param array $roles Список ролей, назначемых создаваемому пользователю.
	 * @param string $confn Имя конфигурационного файла, в котором хранятся настройки защитника.
	 * @throws Defender_Exception Генерируется в случае возникновения ошибок при создании записи пользователя или назначении для него прав.
	 */
	public static function makeUser($userName, $userPasswd, $userActive = FALSE, $roles = array(), $confn = 'defender') {
		$_config = Kohana::$config->load($confn)->as_array(); // Загружаем конфигурационные данные
		$_userModel = self::getUserModel($userName, $_config); // Ищем такого пользователя
		if ($_userModel->loaded() === FALSE) // Если пользователя не существует, то создаём его
			try {
				$_userModel->set($_config['uattr']['username'], $userName)->set($_config['uattr']['password'], $userPasswd)->set($_config['uattr']['active'], $userActive)->create();
			} catch (Exception $_exc) {
				throw new Defender_Exception('Не удалось создать запись пользователя. Причина: :error', array(':error'=>$_exc->getMessage()), 0, $_exc);
			}
		self::addRoleToUser($_userModel, $roles); // Назначаем пользователю права
		return $_userModel; // Возвращаем модель пользователя
	}
	/**
	 * Удаляет запись пользователя.
	 * @param int|string|ORM $user Идентификатор, имя или модель пользователя.
	 * @param string $confn Имя конфигурационного файла, в котором хранятся настройки защитника.
	 * @throws Defender_Exception Генерируется в случае возникновения ошибок при создании записи пользователя или назначении для него прав.
	 */
	public static function deleteUser($user, $confn = 'defender') {
		$_config = Kohana::$config->load($confn)->as_array(); // Загружаем конфигурационные данные
		$_userModel = self::getUserModel($user, $_config); // Ищем пользователя
		if ($_userModel->loaded() === TRUE) // Если пользователь существует, то удаляем его
			try {
				$_userModel->delete();
			} catch (Exception $_exc) {
				throw new Defender_Exception('Не удалось удалить запись пользователя. Причина: :error', array(':error'=>$_exc->getMessage()), 0, $_exc);
			}
	}
	/**
	 * Осуществляет добавление роли(ей) для указанного пользователя.
	 * @param int|string|ORM $user Идентификатор, имя или модель пользователя.
	 * @param int|string|array|ORM $role Идентификатор или название добавляемой роли.
	 * @param string $confn Имя используемой конфигурации.
	 * @throws Defender_Exception Генерируется в том случае, если не определён драйвер для доступа к БД или указанная запись не найдена.
	 */
	public static function addRoleToUser($user, $role, $confn = 'defender') {
		$_config = Kohana::$config->load($confn)->as_array(); // Загружаем конфигурационные данные
		$_userModel = self::getUserModel($user, $_config);
		$_userRoles = $_userModel->roles->find_all()->as_array($_config['rattr']['id']);
		foreach ((array)$role as $_r) {
			$_roleModelID = self::getRoleModel($_r, $_config)->{$_config['rattr']['id']};
			if(!array_key_exists($_roleModelID, $_userRoles))
				$_userModel->add('role', array($_roleModelID), TRUE);
		}
	}
	/**
	 * Осуществляет удаление роли(ей) для указанного пользователя.
	 * @param int|string $user Идентификатор или имя пользователя.
	 * @param int|string|array|ORM $role Идентификатор или название добавляемой роли.
	 * @param string $confn Имя используемой конфигурации.
	 * @throws Defender_Exception Генерируется в том случае, если не определён драйвер для доступа к БД или указанная запись не найдена.
	 */
	public static function removeRoleToUser($user, $role, $confn = 'defender') {
		$_config = Kohana::$config->load($confn)->as_array(); // Загружаем конфигурационные данные
		$_userModel = self::getUserModel($user, $_config);
		$_userRoles = $_userModel->roles->find_all()->as_array($_config['rattr']['id']);
		foreach ((array)$role as $_r) {
			$_roleModelID = self::getRoleModel($_r, $_config)->{$_config['rattr']['id']};
			if(array_key_exists($_roleModelID, $_userRoles))
				$_userModel->remove('role', array($_roleModelID));
		}
	}


	/**
	 * Возвращает модель данных указанного пользователя.
	 * @param int|string|ORM $user Идентификатор или имя пользователя.
	 * @param Config $config Конфигурационные данные защитника.
	 * @throws Defender_Exception Генерируется в том случае, если не определён драйвер для доступа к БД или указанная запись не найдена.
	 * @return NULL|ORM
	 */
	protected static function getUserModel($user, $config) {
		$_driver = isset($config['driver']) ? $config['driver'] : 'ORM'; // Загружаем из конфигурации движок для доступа к БД
		$_model = NULL;
		if ($user instanceof $_driver) {
			return $user;
		} else {
			switch ($_driver) {
				case 'ORM':
					$_model = ORM::factory(ucfirst($config['user_model']), (is_string($user) ? array($config['uattr']['username'] => $user) : $user)); // В зависимости от типа данных, представленных в $user ищем по имени или ID пользователя
					break;
				default:
					throw new Defender_Exception('В конфигурации защитника не определен драйвер для доступа к БД.');
			}
		}
		return $_model;
	}
	/**
	 * Возвращает модель данных указанной роли.
	 * @param int|string|ORM $role Идентификатор или код роли.
	 * @param Config $config Конфигурационные данные защитника.
	 * @throws Defender_Exception Генерируется в том случае, если не определён драйвер для доступа к БД или указанная запись не найдена.
	 * @return NULL|ORM
	 */
	protected static function getRoleModel($role, $config) {
		$_driver = isset($config['driver']) ? $config['driver'] : 'ORM'; // Загружаем из конфигурации движок для доступа к БД
		$_result = NULL;
		if ($role instanceof $_driver)
			return $role;
		else
			switch ($_driver) {
				case 'ORM':
					$_result = ORM::factory(ucfirst($config['role_model']), (is_string($role) ? array($config['rattr']['rolecode'] => $role) : $role)); // В зависимости от типа данных, представленных в $user ищем по имени или ID пользователя
					break;
				default:
					throw new Defender_Exception('В конфигурации защитника не определен драйвер для доступа к БД.');
			}
		if ($_result->loaded() === TRUE)
			return $_result;
		else
			throw new Defender_Exception('Указанная запись пользователя не найдена.');
	}


	/**
	 * @var string Символы, разрешенные для использования в "соли" для cookies.
	 */
	const SALT = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

	/**
	 * @var Defender_Core Массив экземпляров созданных классов.
	 */
	protected static $_instances = array();
	/**
	 * @var string Название экземпляра класса.
	 */
	protected $_name = '';
	/**
	 * @var array Конфигурационные данные модуля.
	 */
	protected $_config = NULL;
	/**
	 * @var Session Сессия, текущего пользователя.
	 */
	protected $_sess = NULL;
	/**
	 * @var array Массив данных о текущем пользователе.
	 */
	protected $_user = NULL;
	/**
	 * @var array Массив названий ролей текущего пользователя.
	 */
	protected $_roles = array();
	/**
	 * @var array Массив правил, определяющих разрешения для текущего пользователя.
	 */
	protected $_rules = array();


	/**
	 * Конструктор класса.
	 * Осуществляет загрузку сессии и конфигурации модуля для инициализации экземпляра класса.
	 * @param string $name Имя создаваемого экземпляра класса.
	 * @param Config $_config Конфигурационные данные модуля.
	 */
	protected function __construct($name = 'def', $_config = NULL) {
		$this->_name = $name; // Запоминаем имя экземпляра класса
		$this->_config = $_config; // Загружаем конфигурационные данные
		if (!isset($this->_config['cookie']['key'])) { // Если в конфигурации не определен ключ сессии, то создаем его
			$this->_config['cookie']['key'] = 'CK_'.$this->_name;
		}
		if (!isset($this->_config['session']['key'])) { // Если в конфигурации не определен ключ сессии, то создаем его
			$this->_config['session']['key'] = 'SK_'.$this->_name;
		}
		$this->_user = $this->find_user(); // Осуществляем поиск текущего пользователя
	}
	/**
	 * Возвращает объект, соответствующий пользователю (если таковой имеется), в противном случаае вернет FALSE.
	 * @return  object / FALSE
	 */
	public function get_user() {
		if (!isset($this->_user)) { // Если пользователь не определен, то осуществляем его поиск в Сессии
			$this->_user = $this->find_user(); // Загружаем пользователя
		}
		if (is_object($this->_user) AND ($this->_config['prevent_browser_cache'] === TRUE)) { // Если объект, соответствующий пользователю загружен и установлен флаг предотвращения использования кнопки Назад после завершения сеанса
			Response::factory()->headers('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'); // Запрещаем браузеру кэшировать данные для всех ответов, когда пользователь вошел в систему
			Response::factory()->headers('Pragma', 'no-cache');
		}
		return $this->_user; // Возвращаем объект текущего пользователя
	}
	/**
	 * Возвращает текущую сессию. В случае необходимости инициализирует новую сессию.
	 * @param string $id Идентификатор сессии.
	 * @return Session
	 */
	public function get_session($id = NULL) {
		if (!isset($this->_sess)) { // Если сессия не определена, то иниализируем ее
			$this->_sess = Session::instance($this->_config['session']['type'], $id, $this->_config['session']['expiration_session'], $this->_config['session']['expiration_cookie']);
		}
		return $this->_sess; // Возвращает текущую сессию
	}
	/**
	 * Возвращает TRUE, если пользователь вошел в систему, в противном случае FALSE.
	 * @return  boolean
	 */
	public function logged_in() {
		return is_object($this->get_user()); // Если пользователь представлен объектом, то возвращаем TRUE, иначе FALSE
	}
	/**
	 * Производит повторную проверку пароля пользователя.
	 * Может использоваться для подтверждения прав пользователя при попытке выполнить действия,
	 * для которых требуется повышенная безопасность. Применяется даже в том случаае, когда
	 * пользователь прошел аутентификацию.
	 * Пример использования:
	 * if ( $authext->check_password($user, $this->request->post('password'))) {
	 *     // delete account or some other special action
	 * }
	 * @param object $user Объект БД с данными, соответствующими пользователю.
	 * @param String $password Пароль, который необходимо проверить.
	 * @return boolean Результат выполнения проверки пароля.
	 */
	public function check_password($user, $password) {
		return ($user->loaded() === TRUE) AND ($this->check($password, $user->{$this->_config['uattr']['password']}) === TRUE);
	}
	/**
	 * Осуществляет попытку входа пользователя.
	 * @param string $username Имя пользователя.
	 * @param string $password Пароль.
	 * @param boolean $remember Признак разрешить автоматический вход пользователя.
	 * @return mixed Объект, соответствующий пользователю, в противном случае будет сгенерирован Defender_Exception с соответствующим сообщением об ошибке входа.
	 */
	public function login($username, $password, $remember = FALSE) {
		try {
			if (empty($password)) { // Учетные записи с пустыми паролями запрещены, возвращаем FALSE
				throw new Defender_Exception('Пароль не может быть пустым.');
			}
			$user = is_object($username) // Если имя пользователя представлено объектом, то оставляем его, в противном случае загружаем объект из БД
				? $username
				: self::getUserModel($username, $this->_config);
			if ($user->loaded() === FALSE) { // Если информацию о пользователе не удалось загрузить, генерируем исключение
				$this->logging('auth', 'filed', 'Невозможно загрузить информацию о пользователе :user.', array(':user' => $username));
				throw new Defender_Exception('Вы исчерпали лимит попыток доступа.');
			}
			if (isset($this->_config['uattr']['failed_attempts']) AND // Если в конфигурации определен параметр число безуспешных попыток входа
				isset($this->_config['uattr']['last_attempt']) AND // и в конфигурации определен параметр дата и время последней попытки входа
				(count(Arr::get($this->_config, 'rate_limits', array())) > 0)) // и в конфигурации определен массив соответствия числа попыток входа и времени блокировки (для защиты от подбора паролей)
			{
				$attempt = 1 + (int)$user->{$this->_config['uattr']['failed_attempts']}; // Увеличиваем число безуспешных попыток входа
				$last = isset($user->{$this->_config['uattr']['last_attempt']})
					? $user->{$this->_config['uattr']['last_attempt']}
					: NULL; // Запоминаем время последней попытки входа
				if (($attempt > 1) AND !empty($last)) { // Если уже была попытка входа
					ksort($this->_config['rate_limits']); // Сортируем массив соответствия
					foreach (array_reverse($this->_config['rate_limits'], TRUE) as $attempts => $time) { // Пробегаемся по массиву
						if ($attempt > $attempts) { // Если номер попытки входа больше чем разрешенное число попыток
							if ((strtotime($last) + $time) > time()) { // Если время блокировки очередно попытки входа не закончилось, то генерируем исключение
								$this->logging('auth', 'filed', 'Пользователь :user исчерпал лимит попыток входа в систему. Попытка: :attempt, Время блокировки: :time.', array(':user' => $username, ':attempt' => $attempt, ':time' => $time));
								throw new Defender_Exception('Вы исчерпали лимит попыток доступа. Попытайтесь позже через '.$time.' секунд.');
							} else { // Иначе переходим к следующей записи соответствия
								break;
							}
						}
					}
				}
			}
			if ($this->check_password($user, $password) === TRUE) { // Если пароль успешно проверен, то завершаем аутентификацию
				if ($user->{$this->_config['uattr']['active']} == TRUE) { // Если учетная запись активна
					$this->logging('auth', 'success', 'Пользователь :user успешно прошел аутентификацию в системе.', array(':user' => $username));
					return $this->complete_login($user, $remember); // Возвращаем пользователя
				} else {
					$this->logging('auth', 'filed', 'Попытка входа в систему пользователя :user, учетная запись ктоторого была деактивирована ранее системным администратором.', array(':user' => $username));
					throw new Defender_Exception('Вы не можете войти в систему, так как ваша учетная запись деактивирована системным администратором.');
				}
			} else { // Если пароль неверный, то запоминаем число попыток входа и время последней попытки
				if (isset($this->_config['uattr']['failed_attempts'])) {
					$user->{$this->_config['uattr']['failed_attempts']}++;
				}
				if (isset($this->_config['uattr']['last_attempt'])) {
					$user->{$this->_config['uattr']['last_attempt']} = date('Y-m-d H:i:s');
				}
				$user->save(); // Сохраняем новые данные
				$this->logging('auth', 'filed', 'Пользователь :user провалил аутентификацию.', array(':user' => $username));
				throw new Defender_Exception('Неверно введено имя пользователя или пароль. Повторите попытку ввода.');
			}
		} catch (Exception $e) { // При ошибке обнуляем права доступа пользователя
			$this->load_acl(); // Загружаем информацию о правах доступа для гостя
			throw $e; // Генерируем то же самое исключение
		}
	}
	/**
	 * Осуществляет завершение сеанса пользователя и удаление данных сессии и cookie.
	 * @return boolean Признак успешного выхода из системы.
	 */
	public function logout() {
		$_temp = Cookie::get($this->_config['cookie']['key']);
		if (!empty($_temp)) { // Если есть запись в cookie, то удаляем ее
			Cookie::delete($this->_config['cookie']['key']);
		}
		$this->get_session()->destroy();
		$this->get_session()->regenerate();
		$this->logging('auth', 'success', 'Пользователь :user вышел из системы.', array(':user' => $this->_user->{$this->_config['uattr']['username']}));
		unset($this->_user); // Удаляем объект, соответствующий пользователю
		return !$this->logged_in(); // Возвращаем признак успешного выхода из системы
	}
	/**
	 * Осуществляет проверку возможности доступа текущего пользователя к указанному ресурсу.
	 * @param string $control Контрол, к которому необходимо проверить возможность доступа.
	 * @param string $action Действие внутри контрола, к которому необходимо проверить возможность доступа.
	 * @return boolean
	 */
	public function allowed($control = '', $action = '') {
		$control = strtolower($control);
		$action = strtolower($action);
		if (empty($this->_rules))
			return FALSE;
		if (array_key_exists('*', $this->_rules)) { // Если указан подстановочный символ, значит у пользователя неограниченный доступ ко всем контролам и действиям
			return  TRUE;
		} else if (array_key_exists($control, $this->_rules)) {
			if (in_array('*', $this->_rules[$control], TRUE)) { // Если указан полный доступам ко всем действияем внутри контрола
				return TRUE;
			} else if (in_array($action, $this->_rules[$control], TRUE)) { // Если разрешен доступ к контролу и действию данного контрола
				return TRUE;
			}
		}
		return FALSE; // Если доступ не разрешен, значит он запрещён
	}
	/**
	 * Осуществляет проверку наличия у пользователя указанному названию, коду или идентификатору роли. Вернет true - если у пользователя присутствует указанная роль, false - в противном случае.
	 * @param string $role Название, код или идентификатор роли, которое необходимо проверить.
	 * @return bool Вернет true - если у пользователя присутствует указанное название, код или идентификатор роли, false - в противном случае.
	 */
	public function has_role($role) {
		return array_search($role, $this->_roles) !== FALSE ? TRUE: FALSE;
	}
	/**
	 * Осуществляет проверку наличия у пользователя указанных ролей или кодов роли. Вернет true - если у пользователя присутствуют указанные роли или её коды, false - в противном случае.
	 * @param array $roles Массив названий и/или кодов ролей, которые необходимо проверить. Если будет задан не массив, то метод вернёт false.
	 * @param bool $oneOf Признак необходимости проверить присутствие у пользователя любой одной роли из списка.
	 * @return bool Вернет true - если у пользователя присутствует указанные роли или её коды, false - в противном случае.
	 */
	public function has_roles($roles, $oneOf) {
		if (!is_array($roles))
			return false;
		$_result = array_intersect($roles, $this->_roles);
		if ($oneOf === TRUE)
			return (count($_result) > 0) ? TRUE : FALSE;
		else
			return (count($_result) == count($roles)) ? TRUE : FALSE;
	}
	/**
	 * Возвращает объект пользователя, сохраненный в сессии (если необходимо). Если объект не найден, то вернет FALSE.
	 * @return  object / FALSE
	 */
	protected function find_user() {
		$user = $this->get_session()->get($this->_config['session']['key'], NULL); // Загружаем объект пользователя из сессии
		if (is_string($user)) { // Если в сессии хранится имя пользователя
			if ($this->_config['session']['store_user'] === TRUE) { // Если установлен флаг хранить данные пользователя в сессии, то завершаем сеанс
				$this->logout(TRUE); // Завершаем сеанс пользователя и очищаем сессию и cookies
				return FALSE; // Возвращаем FALSE (пользователь не найден)
			}
			$user = self::getUserModel($user, $this->_config); // Загружаем информацию о пользователе из БД
			if ($user->loaded() === TRUE) { // Если объект пользователя загружен
				$this->load_acl($user); // Загружаем информацию о правах доступа для текущего пользователя
				return $user; // Возвращаем информацию о пользователе
			}
		} else if (is_object($user)) { // Если загруженные данные представлены объектом
			if (($user->loaded() === TRUE) && ($this->_config['session']['store_user'] === TRUE)) { // Если объект пользователя загружен и установлен флаг хранить данные пользователя в сессии
				$this->load_acl($user); // Загружаем информацию о правах доступа для текущего пользователя
				return $user; // Возвращаем информацию о пользователе
			} else { // Если не удалось загрузить объект пользователя или он загружен некорректно
				$this->logout(TRUE); // Завершаем сеанс пользователя и очищаем сессию и cookies
				return FALSE; // Возвращаем FALSE (пользователь не найден)
			}
		}
		// Загружаем пользователя из БД, если данные хранятся в cookie
		if ($this->_config['session']['use'] === TRUE) { // Если необходимо использовать сессию
			$token = Cookie::get($this->_config['cookie']['key']); // Извлекаем данные из cookie
			if (!empty($token)) { // Если данные из cookie были загружены
				list($hash, $username) = explode('.', $token, 2); // Инициализируем переменные хэш и имя пользователя массивом из двух подстрок, извлеченных $token
				if ((strlen($hash) === 32) && !empty($username)) { // Если длина хэша корректна, и имя пользователя определено
					$user = self::getUserModel($username, $this->_config); // Загружаем данные о пользователе из БД по имени пользователя
					if (($user->loaded() === TRUE) AND ($this->check($hash, $user->{$this->_config['uattr']['token']}) === TRUE)) { // Если загружена информация о пользователе и хэш сессии совпадает с хэшем пароля
						return $this->complete_login($user, TRUE); // Завершаем регистрацию пользователя (обновляем пользовательскую сессию) и возвращаем TRUE
					}
				}
			}
		}
		$this->load_acl(); // Загружаем информацию о правах доступа для текущего пользователя
		return FALSE; // Не удалось найти пользователя, возвращаем FALSE
	}
	/**
	 * Обновляет сессию, устанавливает флаг запомнить в cookie (если необходимо).
	 * @param object $user Объект БД, соответствующий пользовтелю.
	 * @param boolean $remember Флаг, запомнить в cookie.
	 * @return boolean
	 */
	protected function complete_login($user, $remember = FALSE) {
		if (($remember === TRUE) && ($this->_config['session']['use'] === TRUE)) { // Если нужно запомнить в cookie и определено время жизни cookie
			$token = Text::random('alnum', 32); // Формируем ключ
			$user->{$this->_config['uattr']['token']} = $this->hash($token); // Запоминаем в БД хэш ключа
			Cookie::set($this->_config['cookie']['key'], $token.'.'.$user->{$this->_config['uattr']['username']}); // Создаем запись в cookie
		}
		if (isset($this->_config['uattr']['failed_attempts'])) { // Если в конфигурации определен параметр число попыток входа, то сбрасываем число безуспешных попыток входа и время входа
			$user->{$this->_config['uattr']['failed_attempts']} = 0;
			$user->{$this->_config['uattr']['last_attempt']} = NULL;
		}
		if (isset($this->_config['uattr']['last_login'])) { // Если в конфигурации определен параметр время последнего входа, то устанавливаем время последнего входа
			$user->{$this->_config['uattr']['last_login']} = date('Y-m-d H:i:s');
		}
		if (isset($this->_config['uattr']['logins'])) { // Если в конфигурации определен параметр число входов пользователя, то увеличиваем число попыток входа пользователя
			$user->{$this->_config['uattr']['logins']}++;
		}
		$user->save(); // Сохраняем настройки
		$this->get_session()->regenerate(); // Генерируем новую сессию
		// Запоминаем в сессии объект пользователя или имя пользователя
		if ($this->_config['session']['store_user'] === TRUE) {
			$this->get_session()->set($this->_config['session']['key'], $user);
		} else {
			$this->get_session()->set($this->_config['session']['key'], $user->{$this->_config['uattr']['username']});
		}
		$this->load_acl($user); // Загружаем информацию о правах доступа для текущего пользователя
		return $this->_user = $user; // Возвращаем результат
	}
	/**
	 * Осуществляет проверку соответствия хэша пароля и хранимого ключа сессии.
	 * @param string $password Пароль пользователя, который необходимо проверить.
	 * @param string $hash Хэш пароля.
	 * @return boolean Возвращает TRUE, если пароль и хэш совпадают.
	 */
	protected function check($password, $hash) {
		// $2a$ (4) 00 (2) $ (1) <salt> (22)
		preg_match('/^\$2a\$(\d{2})\$(.{22})/D', $hash, $matches);
		// Extract the iterations and salt from the hash
		$cost = Arr::get($matches, 1);
		$salt = Arr::get($matches, 2);
		// return result
		return $this->hash($password, $salt, $cost) === $hash;
	}
	/**
	 * Генерирует bcrypt хэш для указанных данных.
	 * @param string $input Значение хэша.
	 * @param string $salt Соль (опционально, будет сгенерирована в случае отсутствия)
	 * @param int $cost Мощность хэша (опционально, в случае отсутствия будет взято из конфигурации).
	 * @return string Хэш указанных данных.
	 */
	public function hash($input, $salt = NULL, $cost = NULL) {
		if (empty($salt)) { // Если не указана соль, то генерируем ее
			$salt = Text::random(self::SALT, 22);
		}
		if (empty($cost)) { // Если не указана мощность хэша, то генерируем ее
			$cost = $this->_config['cost'];
		}
		$cost = sprintf('%02d', min(31, max($cost, 4))); // Применяем нулевой отступ мощности для нормализации диапазона 4-31
		$salt = '$2a$'.$cost.'$'.$salt.'$'; // Создаем соль, подходящую для bcrypt
		return crypt($input, $salt); // Формируем хэш и возвращаем его
	}
	/**
	 * Осуществляет загрузку информации из БД о правах доступа для указанного пользователя.
	 * @param Model $user Модель данных текущего пользователя.
	 */
	protected function load_acl($user = NULL) {
		$_driver = isset($this->_config['driver']) ? $this->_config['driver'] : 'ORM'; // Загружаем из конфигурации движок для доступа к БД
		$_model = NULL;
		if ($_driver === 'ORM') { // Если используется движок ORM, то возвращаем информацию, загруженную из ORM модели
			if (is_object($user)) {
				$_model = $user->roles->find_all(); // Загружаем все записи в соответствии со связью, описанной в модели пользователя
			} else {
				$_model = ORM::factory(ucfirst($this->_config['role_model']))->where($this->_config['rattr']['rolecode'], '=', 'guest')->find_all();
			}
		} else { // Если не определен движок, то генерируем исключение
			throw new Defender_Exception('В конфигурации защитника не определен драйвер для доступа к БД.');
		}
		foreach ($_model as $rule) {
			$this->_roles[] = $rule->{$this->_config['rattr']['id']};
			$this->_roles[] = $rule->{$this->_config['rattr']['rolename']};
			$this->_roles[] = $rule->{$this->_config['rattr']['rolecode']};
			if (!empty($this->_rules))
				$this->_rules = array_merge_recursive($this->_rules, unserialize($rule->{$this->_config['rattr']['roleact']}));
			else
				$this->_rules = unserialize($rule->{$this->_config['rattr']['roleact']});
		}
	}
	/**
	 * Осуществляет запись сообщения о произошедшем событии в системный журнал событий.
	 * @param string $type Тип произошедшего события (параметры: auth или access как описано в конфигурационном файле).
	 * @param string $event Результат операции (success или filed).
	 * @param string $message Описание произошедшего события.
	 * @param array $values Массив значений, которые будут заменены в тексте сообщения.
	 */
	protected function logging($type, $event, $message, array $values = NULL) {
		if (isset($values[':user']))
			$values[':user'] .= ' (IP: '.Request::$client_ip.')';
		if (isset($this->_config['logging'][$type][$event]) AND ($this->_config['logging'][$type][$event] !== FALSE)) {
			Kohana::$log->add($this->_config['logging'][$type][$event], mb_strtoupper($type.'_'.$event).' = '.$message, $values, array('no_back_trace' => TRUE));
		}
	}

}