<?php defined('SYSPATH') OR die('No direct access allowed.');

/**
 * Класс, представляющий исключение, генерируемое модулем Defender.
 * @package Defender
 * @copyright  (c) 2010-14 RUSproj, Sergey S. Smirnov
 * @author Сергей С. Смирнов
 */
class Defender_Exception extends Kohana_Exception {

	/**
	 * Конструктор класса Defender. 
	 * @param string $message Сообщение о произошедшей ошибке.
	 */
	public function __construct($message) {
		parent::__construct($message);
	}
}