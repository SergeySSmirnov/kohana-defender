<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * Класс модели, предоставляющий доступ к данным ролей конкретных пользователей.
 *  
 * @category Model
 * @copyright  (c) 2010-14 RUSproj, Sergey S. Smirnov
 * @author Сергей С. Смирнов
 */
abstract class Model_Defender_UserRole_ORM extends ORM {

	/**
	 * @var string Имя таблицы в БД.
	 */
	protected $_table_name = 'userroles';
	/**
	 * @var string Имя столбца с первичным ключом.
	 */
	protected $_primary_key = 'pid';
	/**
	 * @var strign Имя столбца, содержащий первичные значения (наиболее востребованные значения).
	 */
	protected $_primary_val = 'rid';
	/**
	 * @var string Суффикс вторичных ключей.
	 */
	protected $_foreign_key_suffix = '';
	/**
	 * @var array Массив, описывающий связи многие-к-одному.
	 */
	protected $_belongs_to = array(
		'Role' => array( // Описание связи с таблицей Роли
			'model' => 'Role', // Имя модели
			'foreign_key' => 'rid' // Вторичный ключ в текущей модели
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
		if (isset($config['userrole_model']))
			$this->_table_name = $config['userrole_model'];
		if (isset($config['urattr']['uid']))
			$this->_primary_key = $config['urattr']['uid'];
		if (isset($config['urattr']))
			$this->_primary_val = $this->_belongs_to['role']['foreign_key'] = $config['urattr']['rid'];		
		if (isset($config['role_model']))
			$this->_belongs_to['role']['model'] = ucfirst($config['role_model']);
	}

}
