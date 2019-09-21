<?php
namespace RUSproj\Kohana\Defender\Defender;

use RUSproj\Kohana\Defender\Defender;
use Arr, Config_Group, Date, Exception, Kohana, Kohana_Exception, ORM, Request, Session, Session_Exception, Text;

/**
 * Defender core class for user authentication and authorization.
 *
 * Use bcrypt.
 * Based on Kohana's AUTH, Fred Wu's AUTHLITE и Woody Gilk's Bonafide.
 *
 * @see http://codahale.com/how-to-safely-store-a-password/
 * @package Defender
 * @copyright (c) 2011 Wouter
 * @copyright (c) 2011 Woody Gilk
 * @copyright (c) 2011 Fred Wu
 * @copyright (c) 2011 Kohana Team
 * @copyright (c) 2010-19 RUSproj, Sergei S. Smirnov
 * @license MIT
 */
abstract class Defender_Core
{

    /**
     * Конфигурационные данные модуля.
     * @var Config_Group
     */
    protected static $config = null;

    /**
     * Экземпляр класса безопасности.
     * @var Defender
     */
    protected static $instance = null;

    /**
     * Сессия, текущего пользователя.
     * @var Session
     */
    protected static $sess = null;

    /**
     * Генерирует bcrypt хэш для указанных данных.
     * @param string $input Значение хэша.
     * @param string $salt Соль (опционально, будет сгенерирована в случае отсутствия).
     * @param int $cost Мощность хэша (опционально, в случае отсутствия будет взято из конфигурации).
     * @return string Хэш указанных данных.
     */
    public static function hash(string $input, string $salt = null, int $cost = null): string {
        if (empty($salt)) { // Если не указана соль, то генерируем ее
            $salt = Text::random('alnum', 22);
        }
        if (empty($cost)) { // Если не указана мощность хэша, то генерируем ее
            $cost = self::$config['cost'];
        }
        $cost = sprintf('%02d', min(31, max($cost, 4))); // Применяем нулевой отступ мощности для нормализации диапазона 4-31
        $salt = '$2a$' . $cost . '$' . $salt . '$'; // Создаем соль, подходящую для bcrypt
        return crypt($input, $salt); // Формируем хэш и возвращаем его
    }

    /**
     * Создаёт запись пользователя с указанными параметрами. Если пользователь с таким логином существует, то ему будут назначены лишь указанные права.
     * @param string $userName Имя пользователя, которого необходимо создать.
     * @param string $userPasswd Пароль создаваемого пользователя.
     * @param boolean $userActive Признак что пользователь должен иметь статус "Активен".
     * @param array $roles Список ролей, назначемых создаваемому пользователю.
     * @param string|Config_Group $config Конфигурационные данные модуля или название конфигурации.
     * @return Defender Объект безопасности (экземпляр класса Defender).
     */
    public static function create(string $userName, string $userPasswd, bool $userActive = FALSE, array $roles = [], $config = 'defender'): Defender {
        self::initConfig($config); // Инициализируем конфигурацию
        if (!is_object(self::getUserModel($userName))) { // Если пользователя не существует, то создаём его
            ORM::factory(ucfirst(self::$config['user_model']))
                ->set(self::$config['uattr']['username'], $userName)
                ->set(self::$config['uattr']['password'], $userPasswd)
                ->set(self::$config['uattr']['active'], $userActive)
                ->create();
        }
        $_defender = self::instance($userName);
        $_defender->addRole($roles); // Назначаем пользователю права
        return $_defender; // Возвращаем объект безопасности
    }

    /**
     * Возвращает объект безопасности (экземпляр класса Defender).
     * @param string $userName Имя пользователя для которого необходимо получить объект безопасности.
     * @param string|Config_Group $config Конфигурационные данные модуля или название конфигурации.
     * @return Defender Объект безопасности (экземпляр класса Defender).
     * @throws Defender_Exception Генерируется в случае ошибок инициализации объекта безопасности.
     * @throws Session_Exception Генерируется в том случае, если время бездействия пользователя истекло.
     */
    public static function instance(string $userName = '', $config = 'defender'): Defender {
        if (isset(self::$instance) && empty($userName)) { // Пытаемся сразу же вернуть существующий экземпляр безопасности
            return self::$instance;
        }
        if (CRYPT_BLOWFISH !== 1) { // Если сервер не поддерживает bcrypt, то генерируем исключение
            throw new Defender_Exception('Данный сервер не поддерживает возможность хэширования bcrypt.');
        }
        self::initConfig($config); // Инициализируем конфигурацию
        self::$sess = Session::instance(self::$config['session']['type']); // Получаем сессию текущего пользователя
        $_lastTime = self::$sess->get(self::$config['session']['key'] . '_TIME', null); // Дата и время последнего обращения пользователя к системе
        $_defender = new Defender(self::getUserModel(empty($userName) ? self::$sess->get(self::$config['session']['key'], null) : $userName)); // Формируем объект безопасности
        if (($_lastTime > 0) && ($_lastTime <= time())) { // Если время бездействия истекло, то закрываем сеанс и генерируем исключение
            self::logout();
            throw new Session_Exception('Сессия завершена в связи с бездействием более ' . self::$config['session']['expiration'] . ' секунд.');
        }
        if (empty($userName)) { // Если запрашиваем информацию о текущем пользователе, то запоминаем его
            self::$instance = $_defender;
        }
        self::$sess->set(self::$config['session']['key'] . '_TIME', time() + self::$config['session']['expiration']); // Запоминаем время завершения сеанса пользователя по бездействию
        return $_defender;
    }

    /**
     * Осуществляет попытку входа пользователя и возвращает объект безопасности (экземпляр класса Defender).
     * @param string $userName Имя пользователя.
     * @param string $password Пароль.
     * @param string|Config_Group $config Конфигурационные данные модуля или название конфигурации.
     * @return Defender Объект безопасности (экземпляр класса Defender).
     * @throws Defender_Exception Генерируется в случае ошибок инициализации объекта безопасности.
     * @throws Kohana_Exception Генерируется в том случае, если сервер не поддерживает Bcrypt.
     * @throws Session_Exception Генерируется в том случае, если время бездействия пользователя истекло.
     */
    public static function login(string $userName, string $password, $config = 'defender'): Defender {
        try {
            if (empty($password)) { // Учетные записи с пустыми паролями запрещены
                throw new Defender_Exception('Пароль не может быть пустым.');
            }
            if (CRYPT_BLOWFISH !== 1) { // Если сервер не поддерживает bcrypt, то генерируем исключение
                throw new Defender_Exception('Данный сервер не поддерживает возможность хэширования bcrypt.');
            }
            self::initConfig($config); // Инициализируем конфигурацию
            $_user = self::getUserModel($userName); // Получаем модель пользователя
            if (!is_object($_user)) { // Если информацию о пользователе не удалось загрузить, генерируем исключение
                self::logEvent('auth', 'filed', 'Невозможно загрузить информацию о пользователе :user.', [':user' => $userName]);
                throw new Defender_Exception('Вы исчерпали лимит попыток доступа.');
            }
            if (!$_user->get(self::$config['uattr']['active'])) { // Если учётная запись деактивирована, то генерируем исключение
                self::logEvent('auth', 'filed', 'Попытка входа в систему пользователя :user, учетная запись которого была деактивирована ранее системным администратором.', [':user' => $userName]);
                throw new Defender_Exception('Вы не можете войти в систему, так как ваша учетная запись деактивирована системным администратором.');
            }
            if (isset(self::$config['uattr']['failed_attempts']) && // Если в конфигурации определен параметр число безуспешных попыток входа
                isset(self::$config['uattr']['last_attempt']) && // и в конфигурации определен параметр дата и время последней попытки входа
                (count(Arr::get(self::$config, 'rate_limits', [])) > 0)) // и в конфигурации определен массив соответствия числа попыток входа и времени блокировки (для защиты от подбора паролей)
            {
                $_attempt = 1 + (int)$_user->get(self::$config['uattr']['failed_attempts']); // Увеличиваем число безуспешных попыток входа
                if (($_attempt > 1) && !empty($_user->get(self::$config['uattr']['last_attempt']))) { // Если уже была попытка входа
                    ksort(self::$config['rate_limits']); // Сортируем массив соответствия
                    foreach (array_reverse(self::$config['rate_limits'], true) as $attempts => $time) { // Пробегаемся по массиву
                        if ($_attempt > $attempts) { // Если номер попытки входа больше чем разрешенное число попыток
                            if ((strtotime($_user->get(self::$config['uattr']['last_attempt'])) + $time) > time()) { // Если время блокировки очередно попытки входа не закончилось, то генерируем исключение
                                self::logEvent('auth', 'filed', 'Пользователь :user исчерпал лимит попыток входа в систему. Попытка: :attempt, Время блокировки: :time.', [':user' => $userName, ':attempt' => $_attempt, ':time' => $time]);
                                throw new Defender_Exception('Вы исчерпали лимит попыток доступа. Попытайтесь позже через ' . $time . ' секунд.');
                            } else { // Иначе переходим к следующей записи соответствия
                                break;
                            }
                        }
                    }
                }
            }
            if (self::check($password, $_user->get(self::$config['uattr']['password']))) { // Если пароль успешно проверен, то завершаем аутентификацию
                if (isset(self::$config['uattr']['failed_attempts']) && isset(self::$config['uattr']['last_attempt'])) { // Если в конфигурации определен параметр число попыток входа, то сбрасываем число безуспешных попыток входа и время входа
                    $_user->set(self::$config['uattr']['failed_attempts'], 0)->set(self::$config['uattr']['last_attempt'], null);
                }
                if (isset(self::$config['uattr']['last_login'])) { // Если в конфигурации определен параметр время последнего входа, то устанавливаем время последнего входа
                    $_user->set(self::$config['uattr']['last_login'], Date::formatted_time('now', 'Y-m-d H:i:s'));
                }
                if (isset(self::$config['uattr']['logins'])) { // Если в конфигурации определен параметр число входов пользователя, то увеличиваем число попыток входа пользователя
                    $_user->set(self::$config['uattr']['logins'], $_user->get(self::$config['uattr']['logins']) + 1);
                }
                $_user->save(); // Сохраняем настройки
                self::$instance = new Defender($_user); // Формируем объект безопасности
                if (!isset(self::$sess)) {
                    self::$sess = Session::instance(self::$config['session']['type']); // Генерируем новую сессию
                }
                self::$sess->regenerate(); // Генерируем новую сессию
                self::$sess->set(self::$config['session']['key'], $userName); // Запоминаем в сессии имя пользователя
                self::$sess->set(self::$config['session']['key'] . '_TIME', time() + self::$config['session']['expiration']); // Запоминаем в сессии время завершения сеанса пользователя по бездействию
                self::logEvent('auth', 'success', 'Пользователь :user успешно прошел аутентификацию в системе.', [':user' => $userName]);
                return self::$instance;
            } else { // Если пароль неверный, то запоминаем число попыток входа и время последней попытки
                if (isset(self::$config['uattr']['failed_attempts'])) {
                    $_user->set(self::$config['uattr']['failed_attempts'], $_user->get(self::$config['uattr']['failed_attempts']) + 1);
                }
                if (isset(self::$config['uattr']['last_attempt'])) {
                    $_user->set(self::$config['uattr']['last_attempt'], Date::formatted_time('now', 'Y-m-d H:i:s'));
                }
                $_user->save(); // Сохраняем новые данные
                self::logEvent('auth', 'filed', 'Пользователь :user провалил аутентификацию.', [':user' => $userName]);
                throw new Defender_Exception('Неверно введено имя пользователя или пароль. Повторите попытку ввода.');
            }
        } catch (Exception $e) { // При ошибке обнуляем права доступа пользователя
            self::$instance = new Defender(); // Загружаем информацию о правах доступа для гостя
            throw $e; // Генерируем то же самое исключение
        }
    }

    /**
     * Осуществляет завершение сеанса пользователя и удаление данных сессии и cookie.
     */
    public static function logout() {
        self::$sess->destroy();
        self::$sess->regenerate();
        self::logEvent('auth', 'success', 'Пользователь :user вышел из системы.', [':user' => self::getUserName()]);
        self::$instance = new Defender(); // Загружаем объект безопасности для гостя
    }

    /**
     * Возвращает сессию текущего пользователя. В случае необходимости инициализирует новую сессию.
     * @return Session
     */
    public static function getSession(): Session {
        if (!isset(self::$sess)) {
            self::$sess = Session::instance(self::$config['session']['type']);
        }
        return self::$sess;
    }

    /**
     * Возвращает имя учётной записи текущего пользователя.
     * @return string Имя учётной записи текущего пользователя.
     */
    public static function getUserName(): string {
        $_user = isset(self::$instance) ? self::$instance->getUser() : null;
        return (is_object($_user) ? $_user->{self::$config['uattr']['username']} : 'Гость');
    }

    /**
     * Возвращает true, если пользователь вошел в систему, в противном случае false.
     * @return  boolean
     */
    public static function isUser(): bool {
        return isset(self::$instance) && is_object(self::$instance->getUser());
    }

    /**
     * При необходимости осуществляет инициализацию конфигурации.
     * @param string|Config_Group $config Конфигурационные данные модуля или название конфигурации.
     */
    protected static function initConfig($config = 'defender') {
        if (!isset(self::$config)) { // При необходимости загружаем файл с конфигурацией модуля
            self::$config = is_string($config) ? Kohana::$config->load($config) : $config;
        }
    }

    /**
     * Возвращает модель данных указанного пользователя.
     * @param int|string|ORM $user Идентификатор, имя или модель пользователя.
     * @return null|ORM Модель данных указанного пользователя. Если пользователь не существует, то вернёт null.
     */
    protected static function getUserModel($user) {
        $_model = null;
        if ($user instanceof ORM) {
            return $user;
        } else {
            $_model = ORM::factory(self::$config['user_model'], (is_string($user) ? [self::$config['uattr']['username'] => $user] : $user)); // В зависимости от типа данных, представленных в $user ищем по имени или ID пользователя
            if (!$_model->loaded()) {
                $_model = null;
            }
        }
        return $_model;
    }

    /**
     * Возвращает модель данных указанной роли.
     * @param int|string|ORM $role Идентификатор или код роли.
     * @throws Defender_Exception Генерируется в том случае, если не определён драйвер для доступа к БД или указанная запись не найдена.
     * @return ORM Модель данных указанной роли. Если роль не существует, то вернёт null.
     */
    protected static function getRoleModel($role): ORM {
        $_model = null;
        if ($role instanceof ORM) {
            return $role;
        } else {
            $_model = ORM::factory(self::$config['role_model'], (is_string($role) ? [self::$config['rattr']['rolecode'] => $role] : $role)); // В зависимости от типа данных, представленных в $role ищем по имени или ID роли
            if (!$_model->loaded()) {
                throw new Defender_Exception('Указанная запись роли не найдена.');
            }
        }
        return $_model;
    }

    /**
     * Осуществляет запись сообщения о произошедшем событии в системный журнал событий.
     * @param string $type Тип произошедшего события (параметры: auth или access как описано в конфигурационном файле).
     * @param string $event Результат операции (success или filed).
     * @param string $message Описание произошедшего события.
     * @param array $values Массив значений, которые будут заменены в тексте сообщения.
     */
    protected static function logEvent(string $type, string $event, string $message, array $values = null) {
        if (!isset($values[':user'])) {
            $values[':user'] .= self::getUserName();
        }
        $values[':user'] .= ' (IP: ' . Request::$client_ip . ')';
        if (isset(self::$config['logging'][$type][$event]) && (self::$config['logging'][$type][$event] !== false)) {
            Kohana::$log->add(self::$config['logging'][$type][$event], mb_strtoupper($type . '_' . $event) . ' = ' . $message, $values, ['no_back_trace' => true]);
        }
    }

    /**
     * Осуществляет проверку соответствия хэша пароля и хранимого ключа сессии.
     * @param string $password Пароль пользователя, который необходимо проверить.
     * @param string $hash Хэш пароля.
     * @return boolean Возвращает true, если пароль и хэш совпадают.
     */
    protected static function check(string $password, string $hash): bool {
        $matches = [];
        // $2a$ (4) 00 (2) $ (1) <salt> (22)
        preg_match('/^\$2a\$(\d{2})\$(.{22})/D', $hash, $matches);
        // Extract the iterations and salt from the hash
        $_cost = Arr::get($matches, 1);
        $_salt = Arr::get($matches, 2);
        // return result
        return self::hash($password, $_salt, $_cost) === $hash;
    }

    /**
     * Данные о текущем пользователе. Если текущй пользователь - Гость, то значение равно null.
     * @var object
     */
    protected $user = null;

    /**
     * Массив названий ролей текущего пользователя.
     * @var array
     */
    protected $roles = [];

    /**
     * Массив правил, определяющих разрешения для текущего пользователя.
     * @var array
     */
    protected $rules = [];

    /**
     * Инициализирует экземпляр класса Defender.
     * @param ORM $user Модель пользователя для которого необходимо получить объект безопасности.
     */
    protected function __construct($user = null) {
        $this->user = is_object($user) ? $user : null; // Запоминаем объект информации о пользователе
        $_rolesModel = null;
        if (is_object($user)) {
            $_rolesModel = $user->get(self::$config['uattr']['roles'])->find_all(); // Загружаем все записи в соответствии со связью, описанной в модели пользователя
        } else {
            $_rolesModel = [ORM::factory(self::$config['role_model'], [self::$config['rattr']['rolecode'] => 'guest'])];
        }
        foreach ($_rolesModel as $_rule) { // Запоминаем роли и допустимые действия пользователя в отдельном массиве
            $this->roles[] = $_rule->get(self::$config['rattr']['id']);
            $this->roles[] = $_rule->get(self::$config['rattr']['rolename']);
            $this->roles[] = $_rule->get(self::$config['rattr']['rolecode']);
            if (!empty($this->rules)) {
                $this->rules = array_merge_recursive($this->rules, unserialize($_rule->get(self::$config['rattr']['roleact'])));
            } else {
                $this->rules = unserialize($_rule->get(self::$config['rattr']['roleact']));
            }
        }
    }

    /**
     * Возвращает объект, соответствующий пользователю (если таковой имеется), в противном случае вернет null.
     * @return ORM
     */
    public function getUser() {
        return $this->user; // Возвращаем объект текущего пользователя
    }

    /**
     * Осуществляет проверку наличия у пользователя указанному названию, коду или идентификатору роли. Вернет true - если у пользователя присутствует указанная роль, false - в противном случае.
     * @param string $role Название, код или идентификатор роли, которое необходимо проверить.
     * @return boolean Вернет true - если у пользователя присутствует указанное название, код или идентификатор роли, false - в противном случае.
     */
    public function hasRole(string $role): bool {
        return array_search($role, $this->roles) !== false ? true : false;
    }

    /**
     * Осуществляет проверку наличия у пользователя указанных ролей или кодов роли. Вернет true - если у пользователя присутствуют указанные роли или её коды, false - в противном случае.
     * @param array $roles Массив названий и/или кодов ролей, которые необходимо проверить. Если будет задан не массив, то метод вернёт false.
     * @param boolean $oneOf Признак необходимости проверить присутствие у пользователя любой одной роли из списка.
     * @return boolean Вернет true - если у пользователя присутствует указанные роли или её коды, false - в противном случае.
     */
    public function hasRoles(array $roles, bool $oneOf): bool {
        if (!is_array($roles)) {
            return false;
        }
        $_result = array_intersect($roles, $this->roles);
        if ($oneOf) {
            return count($_result) > 0;
        } else {
            return count($_result) == count($roles);
        }
    }

    /**
     * Осуществляет проверку возможности доступа текущего пользователя к указанному ресурсу.
     * @param string $control Контрол, к которому необходимо проверить возможность доступа.
     * @param string $action Действие внутри контрола, к которому необходимо проверить возможность доступа.
     * @return boolean
     */
    public function isAllowed(string $control = '', string $action = ''): bool {
        $control = strtolower($control);
        $action = strtolower($action);
        if (empty($this->rules)) {
            return false;
        }
        if (array_key_exists('*', $this->rules)) { // Если указан подстановочный символ, значит у пользователя неограниченный доступ ко всем контролам и действиям
            return true;
        } elseif (array_key_exists($control, $this->rules)) {
            if (in_array('*', $this->rules[$control], true)) { // Если указан полный доступам ко всем действияем внутри контрола
                return true;
            } elseif (in_array($action, $this->rules[$control], true)) { // Если разрешен доступ к контролу и действию данного контрола
                return true;
            }
        }
        return false; // Если доступ не разрешен, значит он запрещён
    }

    /**
     * Возвращает признак того, что текущий пользователь является суперадминистратором.
     * @return boolean Признак того, что текущий пользователь является суперадминистратором.
     */
    public function isSA(): bool {
        return $this->hasRole('sa');
    }

    /**
     * Производит повторную проверку пароля текущего пользователя.
     * Может использоваться для подтверждения прав пользователя при попытке выполнить действия, для которых требуется повышенная безопасность. Применяется даже в том случаае, когда пользователь прошел аутентификацию.
     * @example
     * if ( $authext->check_password($user, $this->request->post('password'))) {
     *     // delete account or some other special action
     * }
     * @param object $user Объект БД с данными, соответствующими пользователю.
     * @param string $password Пароль, который необходимо проверить.
     * @return boolean Результат выполнения проверки пароля.
     */
    public function checkPassword($password): bool {
        if (!is_object($this->user)) {
            return false;
        }
        $_passwHash = $this->user->get(self::$config['uattr']['password']);
        return self::check($password, $_passwHash);
    }

    /**
     * Удаляет запись пользователя.
     */
    public function delete() {
        if (is_object($this->user)) { // Если пользователь существует, то пытаемся удалить его
            $this->user->delete();
        }
    }

    /**
     * Осуществляет добавление роли(ей) для пользователя.
     * @param int|string|array|ORM $role Идентификатор или название добавляемой роли.
     * @throws Defender_Exception Генерируется в том случае, если не определён драйвер для доступа к БД или указанная запись не найдена.
     */
    public function addRole($role) {
        if (is_object($this->user)) { // Если пользователь существует, то пытаемся удалить его
            $_userRoles = $this->user->get(self::$config['uattr']['roles'])->find_all()->as_array(self::$config['rattr']['id']);
            foreach ((array)$role as $_r) {
                $_roleModelID = self::getRoleModel($_r)->get(self::$config['rattr']['id']);
                if (!array_key_exists($_roleModelID, $_userRoles)) {
                    $this->user->add(self::$config['uattr']['roles'], [$_roleModelID], true);
                }
            }
        }
    }

    /**
     * Осуществляет удаление роли(ей) для пользователя.
     * @param int|string|array|ORM $role Идентификатор или название добавляемой роли.
     * @param string $confn Имя используемой конфигурации.
     */
    public function removeRole($role) {
        if (is_object($this->user)) { // Если пользователь существует, то пытаемся удалить его
            $_userRoles = $this->user->get(self::$config['uattr']['roles'])->find_all()->as_array(self::$config['rattr']['id']);
            foreach ((array)$role as $_r) {
                $_roleModelID = self::getRoleModel($_r)->get(self::$config['rattr']['id']);
                if (array_key_exists($_roleModelID, $_userRoles)) {
                    $this->user->remove(self::$config['uattr']['roles'], [$_roleModelID]);
                }
            }
        }
    }

}
