<?php defined('SYSPATH') OR die('No direct access allowed.');

/**
 * Класс, представляющий исключение, генерируемое модулем Defender.
 * @package Defender
 * @copyright  (c) 2010-16 RUSproj, Sergey S. Smirnov
 * @author Сергей С. Смирнов
 */
class Defender_Exception extends Kohana_Exception {

	/**
	 * Конструктор класса Defender. 
	 * @example throw new Kohana_Exception('Something went terrible wrong, :user', array(':user' => $user));
	 * @param string $message Сообщение о произошедшей ошибке.
	 * @param array $variables Массив переменных для транслитерации строк.
	 * @param integer|string $code Код исключения.
	 * @param Exception $previous Ссылка на предыдущее исключение.
	 * @return void
	 */
	public function __construct($message = "", array $variables = NULL, $code = 0, Exception $previous = NULL) {
		parent::__construct($message, $variables, $code, $previous);
	}
}