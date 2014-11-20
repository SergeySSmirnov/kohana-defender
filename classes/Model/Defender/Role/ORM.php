<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * Класс модели, предоставляющий доступ к данным ролей.
 *  
 * @category Model
 * @copyright  (c) 2010-14 RUSproj, Sergey S. Smirnov
 * @author Сергей С. Смирнов
 */
abstract class Model_Defender_Role_ORM extends ORM {

	/**
	 * @var string Имя таблицы в БД.
	 */
	protected $_table_name = 'roles';
	/**
	 * @var string Имя столбца с первичным ключом.
	 */
	protected $_primary_key = 'id';

	/**
	 * @var string Суффикс вторичных ключей.
	 */
	protected $_foreign_key_suffix = '';
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
		if (isset($config['role_model']))
			$this->_table_name = $config['role_model'];
		if (isset($config['rattr']['id']))
			$this->_primary_key = $config['rattr']['id'];
	}

}
