<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * Класс модели, предоставляющий доступ к данным пользователей.
 *  
 * @category Model
 * @copyright  (c) 2010-14 RUSproj, Sergey S. Smirnov
 * @author Сергей С. Смирнов
 */
abstract class Model_Defender_User_ORM extends ORM {

	/**
	 * @var string Имя таблицы в БД.
	 */
	protected $_table_name = 'users';
	/**
	 * @var string Имя столбца с первичным ключом.
	 */
	protected $_primary_key = 'id';
	/**
	 * @var strign Имя столбца, содержащий первичные значения (наиболее востребованные значения).
	 */
	protected $_primary_val = 'username';
	/**
	 * @var string Суффикс вторичных ключей.
	 */
	protected $_foreign_key_suffix = '';
	/**
	 * @var array Массив, описывающий связь многие-ко-многим.
	 */
	protected $_has_many = array(
		'role'  => array( // Связь с таблицей Роль
			'model' => 'Role', // Имя модели таблицы Роль
			'through' => 'userroles', // Имя таблицы связи
			'foreign_key' => 'pid', // Имя ключа, мигрирующего в таблицу РолиПользоватлей из таблицы Пользователь
			'far_key' => 'rid',  // Имя ключа, мигрирующего в таблицу РолиПользоватлей из таблицы Роль
		)
	);
	/**
	 * @var string Имя конфигурационного файла.
	 */
	protected $_config = 'defender';


	/**
	 * (non-PHPdoc)
	 * @see Kohana_ORM::_initialize()
	 */
	protected function _initialize() {
		parent::_initialize();
		$config = Kohana::$config->load($this->_config);
		if (isset($config['user_model']))
			$this->_table_name = $config['user_model'];
		if (isset($config['uattr']['id']))
			$this->_primary_key = $config['uattr']['id'];
		if (isset($config['uattr']['username']))
			$this->_primary_val = $config['uattr']['username'];
		if (isset($config['role_model']))
			$this->_has_many['role']['model'] = ucfirst($config['role_model']);
		if (isset($config['userrole_model']))
			$this->_has_many['role']['through'] = $config['userrole_model'];
		if (isset($config['urattr']['uid']))
			$this->_has_many['role']['foreign_key'] = $config['urattr']['uid'];
		if (isset($config['urattr']['rid']))
			$this->_has_many['role']['far_key'] = $config['urattr']['rid'];
	}
	/**
	 * (non-PHPdoc)
	 * @see Kohana_ORM::save()
	 */
	public function save(Validation $validation = NULL) {
		if (array_key_exists($config['uattr']['password'], $this->_changed))
			$this->_object[$config['uattr']['password']] = Defender::instance($this->_config)->hash($this->_object[$config['uattr']['password']]);
		return parent::save($validation);
	}
}
