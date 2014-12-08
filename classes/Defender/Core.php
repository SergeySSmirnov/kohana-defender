<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * Представляет класс ядра модуля пользовательской аутентификации с использованием bcrypt
 * bcrypt рекомендуется многими для безопасного хранения паролей.
 * Больше информации смотрите на сайте: http://codahale.com/how-to-safely-store-a-password/
 *
 * Основан на Kohana's AUTH, Fred Wu's AUTHLITE и Woody Gilk's Bonafide.
 * @category Controller
 * @copyright  (c) 2011 Wouter
 * @copyright  (c) 2011 Woody Gilk
 * @copyright  (c) 2011 Fred Wu
 * @copyright  (c) 2011 Kohana Team
 * @copyright  (c) 2010-14 RUSproj, Sergey S. Smirnov
 * @license    MIT
 */
abstract class Defender_Core {

	/**
	 * @ string Символы, разрешенные для использования в "соли" для cookies.
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
	 * @var array Массив правил, определяющих разрешения для текущего пользователя.
	 */
	protected $_rules = array();

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
	 * Добавляет новое правило, или изменяет существующую роль и одно правило данной роли.
	 * Вместо указания в $control и $action конкретных значений можно использовать '*' - это обозначает полный доступ либо ко всем контролам, либо ко всем действиям внутри контрола.
	 * Например:
	 * add_rule('Guest', '*', '*'); // Полный доступ роли Guest ко всем контролам и действиям, описанным в контролах.
	 * add_rule('Guest', 'example', '*'); // Полный доступ роли Guest ко всем действиям, описанным в контроле example.
	 * add_rule('Guest', 'example', 'test'); // Доступ роли Guest к действию test, описанному в контроле example.
	 * @param string $rolename Имя новой или редактируемой роли.
	 * @param string $control Контрол, к котрому разрешается доступ для данной роли.
	 * @param string $action Действие контрола, к которому разрешается доступ для данной роли.
	 * @param array $config Конфигурационные данные модуля.
	 * @param string $confn Имя конфигурационного файла.
	 */
	public static function add_rule($rolename, $control, $action, $config = NULL, $confn = 'defender') {
		Defender_Core::add_rules($rolename, array($control => array($action)), $config, $confn);
	}
	/**
	 * Добавляет набор новых правил, или изменяет существующую роль и правила данной роли.
	 * Например:
	 * add_rule('Guest', 'array('example'=>array('test', 'test2'))'); // Доступ роли Guest к действиям test и test2, описанным в контроле example.
	 * add_rule('Guest', 'array('example'=>array('*'))'); // Полный доступ роли Guest ко всем действиям, описанным в контроле example.
	 * add_rule('Guest', 'array('*'=>array('*'))'); // Полный доступ роли Guest ко всем контролам и действиям, описанным в контролах.
	 * @param string $rolename Имя новой или редактируемой роли.
	 * @param array $arules Массив правил доступа роли.
	 * @param array $config Конфигурационные данные модуля.
	 * @param string $confn Имя конфигурационного файла.
	 * @throws Kohana_Exception Исключение генерируется в случае ошибки работы одного из компонентов фреймворка, например, при загрузке конфигурации. 
	 * @throws ORM_Validation_Exception Исключение генерируется в случае неверных данных, которые не соответствуют правилам проверки, описанным в модели.
	 */
	public static function add_rules($rolename, $arules, $config = NULL, $confn = 'defender') {
		if (is_null($config)) { // Загружаем конфигурационный файл, если он не определен
			$_config = Kohana::$config->load($confn);
		}
		$_driver = isset($_config['driver']) ? $_config['driver'] : 'ORM'; // Загружаем из конфигурации имя движка для доступа к БД
		$_model = NULL;
		if ($_driver === 'ORM') { // Если используется движок ORM, то возвращаем информацию, загруженную из ORM модели
			$_model = ORM::factory(ucfirst($_config['role_model']), array($_config['rattr']['rolename'] => $rolename));
		} else { // Если не определен движок, то генерируем исключение
			throw new Defender_Exception('В конфигурации защитника не определен драйвер для доступа к БД.');
		}
		if (array_key_exists('*', $arules)) { // Если разрешен полный доступ ко всем контролам и действиям, то формируем соответствующее правило
			$_rules = array('*' => array('*'));
		} else { // Если разрешен частичный доступ
			if ($_model->loaded() === TRUE) { // Если данные были загружены из БД
				$_rules = unserialize($_model->{$_config['rattr']['roleact']}); // Считываем текущие правила
				if (array_key_exists('*', $_rules)) { // Если разрешен полный доступ ко всем контролам и действиям, то формируем соответствующее правило
					$_rules = array('*' => array('*'));
				} else { // Если доступ к контролам ограничен
					foreach ($arules as $_control => $_crules) { // Пробегаемся по всем контролам
						if (array_key_exists($_control, $_rules)) { // Если контрол существует в загруженных из БД правилах
							if (in_array('*', $_rules[$_control]) || in_array('*', $_crules)) { // Если существует правило доступа ко всем действияем контрола, то добавляем его и переходим к следующему шагу цикла
								$_rules[$_control] = array('*');
								continue;
							} else { // Если права доступа к контролу ограничены
								foreach ($_crules as $id => $action) { // Пробегаемся по всем действиям контрола
									if (in_array($action, $_rules[$_control], TRUE)) { // Если значение уже присутствует, то ничего не делаем
										continue;
									} else { // Иначе добавляем новое действие в контрол
										$_rules[$_control][] = $action;
									}
								}
							}
						} else { // Если контрол не существует в загруженных из БД правилах
							$_rules[$_control] = (in_array('*', $_crules)) ? array('*') : $_crules; // Либо формируем правило доступа ко всем действиям, либо оставлем все так, как есть
						}
					}
				}
			} else { // Если данные не были загружены из БД
				$_model->{$_config['rattr']['rolename']} = $rolename; // Имя правила
				foreach ($arules as $_control => $_crules) { // Пробегаемся по всем контролам
					$_rules[$_control] = (in_array('*', $_crules)) ? array('*') : $_crules; // Либо формируем правило доступа ко всем действиям, либо оставлем все так, как есть
				}
			}
		}
		$_model->{$_config['rattr']['roleact']} = serialize($_rules); // Сериализуем правила
		$_model->save(); // Если данные корректны, то сохраняем их (валидация данных происходит перед операцией сохранения данных)
	}
	/**
	 * Удаляет указанное правило или роль вцелом.
	 * Вместо указания в $control и $action конкретных значений можно использовать '*' - это обозначает либо удаление роли, либо удаление ко всем действиям конкретного контрола.
	 * Например:
	 * delete_rule('Guest', '*', '*') или delete_rule('Guest', '*') или delete_rule('Guest') // Удаление роли Guest.
	 * delete_rule('Guest', 'example', '*') или delete_rule('Guest', 'example') // Удаление доступа роли Guest ко всем действиям, описанным в контроле example.
	 * delete_rule('Guest', 'example', 'test'); // Удаление доступа роли Guest к действию test, описанному в контроле example.
	 * @param string $rolename Имя новой или редактируемой роли.
	 * @param string $control Контрол, к котрому разрешается доступ для данной роли.
	 * @param string $action Действие контрола, к которому разрешается доступ для данной роли.
	 * @param array $config Конфигурационные данные модуля.
	 * @param string $confn Имя конфигурационного файла.
	 * @throws Kohana_Exception Исключение генерируется в случае ошибки работы одного из компонентов фреймворка, например, при загрузке конфигурации. 
	 * @throws ORM_Validation_Exception Исключение генерируется в случае неверных данных, которые не соответствуют правилам проверки, описанным в модели.
	 */
	public static function delete_rule($rolename, $control = '*', $action = '*', $config = NULL, $confn = 'defender') {
		if (is_null($config)) { // Загружаем конфигурационный файл, если он не определен
			$_config = Kohana::$config->load($confn);
		}
		$_driver = isset($_config['driver']) ? $_config['driver'] : 'ORM'; // Загружаем из конфигурации имя движка для доступа к БД
		$_model = NULL;
		if ($_driver === 'ORM') { // Если используется движок ORM, то возвращаем информацию, загруженную из ORM модели
			$_model = ORM::factory(ucfirst($_config['role_model']), array($_config['rattr']['rolename'] => $rolename));
		} else { // Если не определен движок, то генерируем исключение
			throw new Defender_Exception('В конфигурации защитника не определен драйвер для доступа к БД.');
		}
		if ($_model->loaded() === FALSE) { // Если данные не были загружены, то завершаем метод
			return;
		}
		if ($control === '*') { // Если необходимо удалить запись вцелом, то удаляем и завершаем метод
			$_model->delete();
			return;
		}
		$_rules = unserialize($_model->{$_config['rattr']['roleact']}); // Считываем текущие правила
		if ($action === '*') { // Если необходимо удалить все действия
			unset($_rules[$control]);
		} else {
			$_rules[$control] = array_flip($_rules[$control]); // Меняем местами ключи и значения
			unset($_rules[$control][$action]); // Удаляем элемент массива
			$_rules[$control] = array_flip($_rules[$control]); // Меняем местами ключи и значения
		}
		$_model->{$_config['rattr']['roleact']} = serialize($_rules); // Сериализуем правила
		$_model->save(); // Если данные корректны, то сохраняем их
	} 
	
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
				: $this->load_user($username);
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
								throw new Defender_Exception('Вы исчерпали лимит попыток доступа. Попытайтесь позже через :time секунд.', array(':time'=>$time));
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
	 * @param boolean $destroy Признак необходимости польностью удалить сессию.
	 * @return boolean Признак успешного выхода из системы.
	 */
	public function logout($destroy = FALSE) {
		if (!empty(Cookie::get($this->_config['cookie']['key']))) { // Если есть запись в cookie, то удаляем ее
			Cookie::delete($this->_config['cookie']['key']);
		}
		if ($destroy === TRUE) { // Если необходимо, то удаляем сессию
			$this->get_session()->destroy();
		} else { // Иначе удаляем сессию и генерируем новую запись сессии
			$this->get_session()->delete($this->_config['session']['key']);
			$this->get_session()->regenerate();
		}
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
		if (array_key_exists('*', $this->_rules)) { // Если указан подстановочный символ, значит у пользователя неограниченный доступ ко всем контролам и действиям
			return  TRUE;
		} else if (array_key_exists($control, $this->_rules)) {
			if (in_array('*', $this->_rules[$control], TRUE)) { // Если указан полный доступам ко всем действияем внутри контрола 
				return TRUE;
			} else if (in_array($action, $this->_rules[$control], TRUE)) { // Если разрешен доступ к контролу и действию данного контрола
				return TRUE;
			}
		} else { // Если доступ не разрешен, значит он запрещен
			return FALSE;
		}
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
			$user = $this->load_user($user); // Загружаем информацию о пользователе из БД
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
					$user = $this->load_user($username); // Загружаем данные о пользователе из БД по имени пользователя
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
	 * Осуществляет загрузку информации об указанном пользователе из БД.
	 * @param string $username Имя пользователя.
	 * @return object Объект БД с данными, соответствующими пользователю.
	 */
	protected function load_user($username) {
		$_driver = isset($this->_config['driver']) ? $this->_config['driver'] : 'ORM'; // Загружаем из конфигурации движок для доступа к БД
		$model = NULL;
		if ($_driver === 'ORM') { // Если используется движок ORM, то возвращаем информацию, загруженную из ORM модели
			$model = ORM::factory(ucfirst($this->_config['user_model']), array( $this->_config['uattr']['username'] => $username));
		} else { // Если не определен движок, то генерируем исключение
			throw new Defender_Exception('В конфигурации защитника не определен драйвер для доступа к БД.');
		}
		return $model;
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
				$_model = $user->role->find_all();
			} else {
				$_model = ORM::factory('Role')->where($this->_config['rattr']['rolename'], '=', 'Guest')->find_all();
			}
		} else { // Если не определен движок, то генерируем исключение
			throw new Defender_Exception('В конфигурации защитника не определен драйвер для доступа к БД.');
		}
		foreach ($_model as $rule) {
			$this->_rules = array_merge($this->_rules, unserialize($rule->{$this->_config['rattr']['roleact']}));
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
		$message = $message.' Client IP: '.Request::$client_ip.'.';
		if (isset($this->_config['logging'][$type][$event]) AND ($this->_config['logging'][$type][$event] !== FALSE)) {
			Kohana::$log->add($this->_config['logging'][$type][$event], mb_strtoupper($type.'_'.$event).' = '.$message, $values, array('no_back_trace' => TRUE));
		}
	}
	
}