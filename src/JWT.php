<?php
/**
 * Класс для работы с ключами JWT
 * @author Yuri Frantsevich (FYN)
 * Date: 13/08/2021
 * @version 1.0.0
 * @copyright 2021
 */

namespace FYN;

use DateTime;
use Exception;
use FYN\Base;

class JWT {

    /**
     * Имя сессии для токенов
     * @var string
     */
    private $token_cookie_name = 'token';

    /**
     * Время "жизни" простой (гостевой) сессии (сек.)
     * @var int
     */
    private $session_live_time = 3600;

    /**
     * Время "жизни" сохранённой сессии (сек.)
     * @var int
     */
    private $session_live_time_rem = 2592000;

    /**
     * Параметр безопасности для COOKIE
     * @var bool
     */
    private $secure = true;

    /**
     * Параметр безопасности для COOKIE
     * @var bool
     */
    private $http_only = true;

    /**
     * Порядок кроссдоменной передачи куки
     *
     * @var string
     */
    private $samesite = 'lax';

    /**
     * Логи
     * @var array
     */
    private $logs = array();

    /**
     * Имя файла в который сохраняется лог
     * @var string
     */
    private $log_file = 'jwt.log';

    /**
     * Отладочные логи
     */
    private $debug = false;

    /**
     * Класс базовых функций
     * @var object
     */
    private $BASE = [];

    /**
     * JWT constructor.
     */
    public function __construct() {
        if (!defined("SERVER_NAME")) define("SERVER_NAME", $_SERVER['SERVER_NAME']);
        $this->BASE = new FYN\Base();
    }

    /**
     * Завершение работы
     */
    public function __destruct(){
    }

    /**
     * Генерация JWT
     *
     * URL: https://openid.net/developers/specs/
     * URL: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
     *
     * Например:
     * $token = $this->createJWT(array('alg'=>'HS256', 'typ'=>'JWT'), array('iss'=>WWW_PATH, 'exp'=>1551857936, 'jti'=>1, 'user_name'=>'User', 'user_id'=>1), 'security_key_99');
     * header("Authorization: Bearer $token");
     *
     * @param array $header - массив данных заголовка
     *          Заголовки. Обязательный ключ здесь только один:
     *              alg: алгоритм, используемый для подписи/шифрования (в случае не подписанного JWT используется значение «none»).
     *          Необязательные ключи:
     *              typ: тип токена (type). Используется в случае, когда токены смешиваются с другими объектами, имеющими JOSE заголовки. Должно иметь значение «JWT».
     *              cty: тип содержимого (content type). Если в токене помимо зарегистрированных служебных ключей есть пользовательские, то данный ключ не должен присутствовать. В противном случае должно иметь значение «JWT»[2]
     * @param array $user_data - массив пользовательских данных
     *          Пользовательская информация (например, имя пользователя и уровень его доступа), а также могут быть использованы некоторые служебные ключи. Все они являются необязательными:
     *              iss: чувствительная к регистру строка или URI, которая является уникальным идентификатором стороны, генерирующим токен (issuer).
     *              sub: чувствительная к регистру строка или URI, которая является уникальным идентификатором стороны, о которой содержится информация в данном токене (subject). Значения с этим ключом должны быть уникальны в контексте стороны, генерирующей JWT.
     *              aud: массив чувствительных к регистру строк или URI, являющийся списком получателей данного токена. Когда принимающая сторона получает JWT с данным ключом, она должна проверить наличие себя в получателях — иначе проигнорировать токен (audience).
     *              exp: время в формате Unix Time, определяющее момент, когда токен станет не валидным (expiration).
     *              nbf: в противоположность ключу exp, это время в формате Unix Time, определяющее момент, когда токен станет валидным (not before).
     *              jti: строка, определяющая уникальный идентификатор данного токена (JWT ID)
     * @param string $security - ключ шифрования
     * @return mixed
     */
    public function createJWT ($header = array(), $user_data = array(), $security = '') {
        if ($this->debug) $this->logs[] = "JWT Creator: START";
        // ключи заголовка. 1 - обязательные, 0 - необязательные
        $h_keys = array('alg' => 1, 'typ' => 0, 'cty' => 0);
        // ключи пользовательских данных. 1 - обязательные, 0 - необязательные
        $b_keys = array('iss' => 0, 'sub' => 0, 'aud' => 0, 'exp' => 0, 'nbf' => 0, 'jti' => 0);
        // указатель того, что проверка пройдена
        $go = 1;
        // формируем заголовок
        $clear = array();
        foreach ($h_keys as $key=>$ii) {
            if ($ii == 1 && (!isset($header[$key]) || !$header[$key])) {
                if ($this->debug) $this->logs[] = 'JWT Creator Error: Mandatory key '.$key.' not passed';
                $go = 0;
            }
            elseif (isset($header[$key])) $clear[$key] = $header[$key];
        }
        if (!$go || count($clear) < 1) {
            if (count($clear) < 1) $this->logs[] = 'JWT Creator Error: No header!';
            return false;
        }
        else $header = $clear;
        // формируем пользовательские данные
        foreach ($b_keys as $key=>$ii) {
            if ($ii == 1 && (!isset($user_data[$key]) || !$user_data[$key])) {
                if ($this->debug) $this->logs[] = 'JWT Creator Error: Mandatory key '.$key.' not passed';
                $go = 0;
            }
        }
        if (!$go || count($user_data) < 1) {
            if (count($user_data) < 1) $this->logs[] = 'JWT Creator Error: No data!';
            return false;
        }
        // результирующий массив
        $output = array();
        $output[] = static::base64Encode(static::jsonEncode($header));
        $output[] = static::base64Encode(static::jsonEncode($user_data));
        // формируем сигнатуру (подпись). Без ключа шифрования не имеет смысла
        $signature = '';
        if ($security) $signature = static::getSignature(implode('.', $output), $security);
        $output[] = $signature;
        // формируем ключ
        $jwt = implode('.', $output);
        if ($this->debug) $this->logs[] = "Creat JWT: ".$jwt;
        if ($this->debug) $this->logs[] = "JWT Creator: STOP";
        return $jwt;
    }

    /**
     * Декодирование JWT
     * @param string $jwt - JWT токен
     * @param string $security - ключ шифрования
     * @param null $timestamp - фиксированное время жизни токена, необязательный параметр. По умолчанию равен time()
     * @param int $leeway - дополнительное время жизни токена для учёта разницы во времени.
     *
     * URL: https://openid.net/developers/specs/
     * URL: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
     *
     * @return mixed
     * @throws Exception
     */
    public function decodeJWT ($jwt, $security = '', $timestamp = null, $leeway = 0) {
        if (is_array($jwt)) {
            if ($this->debug) $this->logs[] = "Decode JWT: ERROR";
            if ($this->debug) $this->logs[] = "JWT is array: ".print_r($jwt, true);
            $error['info'] = 'JWT is array';
            $error['case'] = 'first check';
            $error = $this->BASE->ArrayToObj($error);
            return $error;
        }
        if ($this->debug) $this->logs[] = "Decode JWT: START";
        if ($this->debug) $this->logs[] = "JWT: ".$jwt;
        $timestamp = is_null($timestamp) ? time() : $timestamp;
        $data = explode('.', $jwt);
        $error = array();
        $error['error'] = true;
        // проверяем количество сегментов в токене
        if (count($data) != 3) {
            try {
                throw new Exception('Wrong number of segments');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'segments';
                $error = $this->BASE->ArrayToObj($error);
                return $error;
            }
        }
        list($head_64, $body_64, $crypto_64) = $data;
        // декодируем первый блок
        if (null === ($header = static::jsonDecode(static::base64Decode($head_64)))){
            try {
                throw new Exception('Invalid header encoding');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'header';
                $error = $this->BASE->ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "JWT Header: ".preg_replace("/\n/", '', print_r($header, true));
        // декодируем второй блок
        if (null === ($payload = static::jsonDecode(static::base64Decode($body_64)))) {
            try {
                throw new Exception('Invalid claims encoding');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'payload';
                $error = $this->BASE->ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "JWT Payload: ".preg_replace("/\n/", '', print_r($payload, true));
        // декодируем сигнатуру
        if (false === ($signature = static::base64Decode($crypto_64))) {
            try {
                throw new Exception('Invalid signature encoding');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'signature';
                $error = $this->BASE->ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "JWT Signature: ".preg_replace("/\n/", '', print_r($signature, true));
        // проверяем наличие информации об алгоритме шифрования
        if (empty($header->alg)) {
            try {
                throw new Exception('Empty algorithm');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'alg';
                $error = $this->BASE->ArrayToObj($error);
                return $error;
            }
        }
        // проверяем сигнатуру. Check the signature
        if (!static::verify("$head_64.$body_64", $signature, $security, 'SHA256')) {
            try {
                throw new Exception('Signature verification failed');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'signature check';
                $error = $this->BASE->ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "JWT signature verified";
        // проверяем параметр nbf
        // nbf: время в формате Unix Time, определяющее момент, когда токен станет валидным (not before).
        // Check if the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($payload->nbf) && $payload->nbf > ($timestamp + $leeway)) {
            try {
                throw new Exception('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->nbf));
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'nbf';
                $error = $this->BASE->ArrayToObj($error);
                return $error;
            }
        }
        // проверяем параметр iat
        // iat: время в формате Unix Time, определяющее момент выпуска токена.
        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($payload->iat) && $payload->iat > ($timestamp + $leeway)) {
            try {
                throw new Exception('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat));
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'iat';
                $error = $this->BASE->ArrayToObj($error);
                return $error;
            }
        }
        // проверяем параметр exp
        // exp: время в формате Unix Time, определяющее момент окончания срока действия токена.
        // Check if this token has expired.
        if (isset($payload->exp) && ($timestamp - $leeway) >= $payload->exp) {
            try {
                throw new Exception('Expired token');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'exp';
                $error = $this->BASE->ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "Decode JWT: STOP";
        return $payload;
    }

    /**
     * Получение данных из шапки и тела токена независимо от сигнатуры
     * Используем, например, для получения ID скомпроментированного клиента
     * @param $jwt - токен
     * @return array
     */
    public function getJWTData ($jwt) {
        if ($this->debug) $this->logs[] = "Get JWT Data: START";
        if ($this->debug) $this->logs[] = "JWT: ".$jwt;
        $data = explode('.', $jwt);
        $result = array();
        if (count($data) > 2) {
            @list($head_64, $body_64, $crypto_64) = $data;
            unset($crypto_64);
            $header = static::jsonDecode(static::base64Decode($head_64));
            $payload = static::jsonDecode(static::base64Decode($body_64));
            if ($header->alg) $result['header'] = (array) $header;
            $result['payload'] = $this->BASE->ObjToArray($payload);
        }
        if ($this->debug) $this->logs[] = "JWT Data: ".preg_replace("/\n/", '', print_r($result, true));
        if ($this->debug) $this->logs[] = "Get JWT Data: STOP";
        return $result;
    }

    /**
     * Проверка подписи
     * @param string $msg - передаваемые данные (заголовок и тело ключа)
     * @param string $signature - подпись
     * @param string $key - ключ шифрования
     * @param string $alg - алгоритм шифрования
     * @return bool
     */
    private function verify ($msg, $signature, $key, $alg = 'SHA256') {
        if ($this->debug) $this->logs[] = "Verify JWT signature";
        $hash = hash_hmac($alg, $msg, $key, true);
        if (function_exists('hash_equals')) {
            return hash_equals($signature, $hash);
        }
        $len = min(static::safeStr_len($signature), static::safeStr_len($hash));
        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            $status |= (ord($signature[$i]) ^ ord($hash[$i]));
        }
        $status |= (static::safeStr_len($signature) ^ static::safeStr_len($hash));
        return ($status === 0);
    }

    /**
     * Декодирование из JSON
     * @param string $input - json строка
     * @param boolean $assoc - возвращать ассоциативный массив или нет
     * @return mixed
     */
    public static function jsonDecode($input, $assoc = false) {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            /**
             * In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you
             * to specify that large ints (like Steam Transaction IDs) should be treated as
             * strings, rather than the PHP default behaviour of converting them to floats.
             */
            $obj = json_decode($input, $assoc, 512, JSON_BIGINT_AS_STRING);
        }
        else {
            /**
             * Not all servers will support that, however, so for older versions we must
             * manually detect large ints in the JSON string and quote them (thus converting
             * them to strings) before decoding, hence the preg_replace() call.
             */
            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints, $assoc);
        }
        return $obj;
    }

    /**
     * Кодирование в JSON
     * @param array $input - массив данных
     * @return false|string
     */
    public static function jsonEncode($input) {
        $json = json_encode($input, JSON_FORCE_OBJECT | JSON_NUMERIC_CHECK | JSON_UNESCAPED_UNICODE);
        return $json;
    }

    /**
     * Кодирование в формат URLBase64
     * @param string $input - строка данных
     * @return mixed
     */
    public static function base64Encode ($input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Декодирование из формата URLBase64
     * @param string $input - строка в формате Base64 URL
     * @return bool|string
     */
    public static function base64Decode ($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $pad_len = 4 - $remainder;
            $input .= str_repeat('=', $pad_len);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Генерация подписи к токену JWT
     * @param string $input - строка для шифрования
     * @param string $key - ключ шифрования
     * @param string $alg - алгоритм шифрования
     * @return mixed
     */
    public static function getSignature ($input, $key, $alg = 'SHA256') {
        return static::base64Encode(hash_hmac($alg, $input, $key, true));
    }

    /**
     * Высчитываем длину строки
     * @param string $str - строка
     * @return int
     */
    private static function safeStr_len($str) {
        if (function_exists('mb_strlen')) return mb_strlen($str, '8bit');
        return strlen($str);
    }

    /**
     * Сохранение JWT в куки браузера
     * @param array $data - данные пользователя
     * @param string $key - ключ шифрования
     * @param array $header - заголовки
     * @param string $cookie_name - имя куки
     * @return mixed
     */
    public function setJWT ($data, $key, $header = array(), $cookie_name = '') {
        if ($this->debug) $this->logs[] = "Set JWT: START";
        if (is_object($data)) $data = (array) $data;
        if (!is_array($data)) {
            $this->logs[] = "Set JWT Error: No data";
            if ($this->debug) $this->logs[] = "Set JWT: STOP";
            return false;
        }
        if (!$cookie_name && $this->token_cookie_name) $cookie_name = $this->token_cookie_name;
        if (!count($header)) $header = array('alg'=>'HS256', 'typ'=>'JWT');
        if (isset($_SESSION['remember']) && $_SESSION['remember']) $live_time = $this->session_live_time_rem;
        else $live_time = $this->session_live_time;
        if (!isset($data['exp']) || !$data['exp']) {
            $data['exp'] = time()+$live_time;
            $exp = time()+$live_time;
        }
        else $exp = $data['exp'];
        if ($key === null) $key = $header['alg'];
        $jwt = static::createJWT($header, $data, $key);
        $domain = (SERVER_NAME != 'localhost' && preg_match("/\./", SERVER_NAME))?SERVER_NAME:false;
        if ($this->debug) $this->logs[] = 'Session domain for JWT: '.$domain;
        if (!defined('IS_API')) setcookie($cookie_name, $this->BASE->getKeyHash($jwt), array('expires'=>$exp, 'path'=>'/', 'domain'=>$domain, 'secure'=>$this->secure, 'httponly'=>$this->http_only, 'samesite'=>$this->samesite));
        if ($this->debug) $this->logs[] = "Set JWT: STOP";
        return $jwt;
    }

    /**
     * Проверка токена JWT, возврат данных
     * @param string $jwt - JWT строка
     * @param string $security - ключ шифрования
     * @param null $timestamp - фиксированное время жизни токена, необязательный параметр. По умолчанию равен time()
     * @param int $leeway - дополнительное время жизни токена для учёта разницы во времени.
     * @return bool|object
     * @throws Exception
     */
    public function checkJWT ($jwt, $security = '', $timestamp = null, $leeway = 0) {
        if ($this->debug) $this->logs[] = "Check JWT: START";
        $data = static::decodeJWT($jwt, $security, $timestamp, $leeway);
        /* ToDo проверка
        if (!isset($data->error) || !$data->error) {
            if ($data && isset($data->exp)) {
                $name = $this->token_cookie_name;
                if ($_SESSION[$name] && $data->exp <= (time() + $this->session_live_time)) {
                    unset($data->exp);
                    $header = array('alg' => 'HS256', 'typ' => 'JWT');
                    $jwt = $this->setJWT($data, CRYPT_KEY, $header, $this->token_cookie_name);
                    $data = static::decodeJWT($jwt, $security, $timestamp, $leeway);
                }
                elseif (isset($data->nbf) && $data->nbf >= $data->exp) $data = false;
            }
            if (isset($data->nbf) && $data->nbf > time()) $data = false;
        }
        */
        if ($this->debug) $this->logs[] = "Check JWT return Data: ".preg_replace("/\n/", '', print_r($data, true));
        if ($this->debug) $this->logs[] = "Check JWT: STOP";
        return $data;
    }

    /**
     * Очистка ключей
     * @return bool
     */
    public function clearJWT () {
        if ($this->debug) $this->logs[] = "Clear JWT: START";
        $domain = (SERVER_NAME != 'localhost' && preg_match("/\./", SERVER_NAME))?SERVER_NAME:false;
        setcookie('token', '', (time()-1), '/', $domain, $this->secure, $this->http_only);
        if (isset($_COOKIE['refresh_token'])) setcookie('refresh_token', '', (time()-1), '/', $domain, $this->secure, $this->http_only);
        if (isset($_COOKIE['API'])) setcookie('API', '', (time()-1), '/', $domain, $this->secure, $this->http_only);
        if (isset($_COOKIE['API_R'])) setcookie('API_R', '', (time()-1), '/', $domain, $this->secure, $this->http_only);
        unset($_COOKIE['token'], $_COOKIE['refresh_token']);
        if ($this->debug) $this->logs[] = "JWT deleted from cookie";
        if ($this->debug) $this->logs[] = "Clear JWT: STOP";
        return true;
    }

    /**
     * Возвращает логи
     * @return array
     */
    public function getLogs () {
        $return['log'] = $this->logs;
        $return['file'] = $this->log_file;
        return $return;
    }
}