<?php
/**
 * Class for working with JWT tokens
 * @author Yuri Frantsevich
 * Date: 13/08/2021
 * @version 2.1.1
 * @copyright 2021-2026
 */

namespace Toropyga;

use DateTime;
use Exception;
use Toropyga\Base;

class JWT {

    /**
     * Session name for tokens
     * @var string
     */
    private $token_cookie_name = 'token';

    /**
     * Lifetime of a simple (guest) session (sec.)
     * @var int
     */
    private $session_live_time = 3600;

    /**
     * Lifetime of a "remembered" session (sec.)
     * @var int
     */
    private $session_live_time_rem = 2592000;

    /**
     * Security parameter for the COOKIE
     * @var bool
     */
    private $secure = true;

    /**
     * Security parameter for the COOKIE
     * @var bool
     */
    private $http_only = true;

    /**
     * Cross-domain cookie transmission policy
     *
     * @var string
     */
    private $samesite = 'lax';

    /**
     * Logs
     * @var array
     */
    private $logs = array();

    /**
     * Name of the file the log is saved to
     * @var string
     */
    private $log_file = 'jwt.log';

    /**
     * Debug logging
     */
    private $debug = false;

    /**
     * Allowed signature algorithms and their corresponding hash_hmac() hash algorithms.
     * Used as a whitelist — tokens with any other "alg" value are rejected.
     * @var array
     */
    private static $allowed_algs = array(
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    );

    /**
     * JWT constructor.
     * @param string $server_name - server name; if not set, taken from $_SERVER['SERVER_NAME']
     */
    public function __construct($server_name = '') {
        if ($server_name) define("SERVER_NAME", $server_name);
        if (!defined("SERVER_NAME")) define("SERVER_NAME", $_SERVER['SERVER_NAME']);
        if (!session_id()) session_start();
    }

    /**
     * Destructor
     */
    public function __destruct(){
    }

    /**
     * JWT generation
     *
     * URL: https://openid.net/developers/specs/
     * URL: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
     *
     * Example:
     * $token = $this->createJWT(array('alg'=>'HS256', 'typ'=>'JWT'), array('iss'=>WWW_PATH, 'exp'=>1551857936, 'jti'=>1, 'user_name'=>'User', 'user_id'=>1), 'security_key_99');
     * header("Authorization: Bearer $token");
     *
     * @param array $header - header data array
     *          Headers. Only one key is mandatory here:
     *              alg: the algorithm used for signing/encryption (for an unsigned JWT the value "none" is used).
     *          Optional keys:
     *              typ: token type. Used when tokens are mixed with other objects that have JOSE headers. Should have the value "JWT".
     *              cty: content type. If the token, besides the registered service keys, has custom ones, this key should not be present. Otherwise it should have the value "JWT"[2]
     * @param array $user_data - array of user data
     *          User information (e.g. username and access level), and some service keys may also be used. All of them are optional:
     *              iss: a case-sensitive string or URI that is the unique identifier of the party generating the token (issuer).
     *              sub: a case-sensitive string or URI that is the unique identifier of the party this token contains information about (subject). Values with this key must be unique within the context of the party generating the JWT.
     *              aud: an array of case-sensitive strings or URIs listing the intended recipients of this token. When a receiving party gets a JWT with this key, it must check whether it is among the recipients — otherwise the token should be ignored (audience).
     *              exp: Unix Time defining the moment the token becomes invalid (expiration).
     *              nbf: opposite of the exp key, Unix Time defining the moment the token becomes valid (not before).
     *              jti: a string defining the unique identifier of this token (JWT ID)
     * @param string $security - encryption key
     * @return mixed
     */
    public function createJWT ($header = array(), $user_data = array(), $security = '') {
        if ($this->debug) $this->logs[] = "JWT Creator: START";
        // header keys. 1 - mandatory, 0 - optional
        $h_keys = array('alg' => 1, 'typ' => 0, 'cty' => 0);
        // user data keys. 1 - mandatory, 0 - optional
        $b_keys = array('iss' => 0, 'sub' => 0, 'aud' => 0, 'exp' => 0, 'nbf' => 0, 'jti' => 0);
        // flag indicating the check has passed
        $go = 1;
        // build the header
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
        // build the user data
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
        // the signing algorithm must be in the allowed list — reject any arbitrary/spoofed "alg"
        if (!isset(static::$allowed_algs[$header['alg']])) {
            $this->logs[] = 'JWT Creator Error: Unsupported alg "'.$header['alg'].'"';
            if ($this->debug) $this->logs[] = "JWT Creator: STOP";
            return false;
        }
        // the encryption key is mandatory. Creating an unsigned token is not allowed.
        if (!is_string($security) || $security === '') {
            $this->logs[] = 'JWT Creator Error: Security key is required, unsigned tokens are not allowed';
            if ($this->debug) $this->logs[] = "JWT Creator: STOP";
            return false;
        }
        // resulting array
        $output = array();
        $output[] = static::base64Encode(static::jsonEncode($header));
        $output[] = static::base64Encode(static::jsonEncode($user_data));
        // build the signature
        $output[] = static::getSignature(implode('.', $output), $security, static::$allowed_algs[$header['alg']]);
        // build the token
        $jwt = implode('.', $output);
        // IMPORTANT: do not log the token itself or user data in plain form even in debug mode,
        // to avoid writing sensitive data to the log file.
        if ($this->debug) $this->logs[] = "JWT Creator: token generated, length=".static::safeStr_len($jwt);
        if ($this->debug) $this->logs[] = "JWT Creator: STOP";
        return $jwt;
    }

    /**
     * JWT decoding
     * @param string $jwt - JWT token
     * @param string $security - encryption key
     * @param null $timestamp - fixed token lifetime timestamp, optional parameter. Defaults to time()
     * @param int $leeway - additional token lifetime allowance to account for clock skew.
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
            if ($this->debug) $this->logs[] = "JWT is array, expected string";
            $error['info'] = 'JWT is array';
            $error['case'] = 'first check';
            $error = Base::ArrayToObj($error);
            return $error;
        }
        if ($this->debug) $this->logs[] = "Decode JWT: START";
        $timestamp = is_null($timestamp) ? time() : $timestamp;
        $data = explode('.', $jwt);
        $error = array();
        $error['error'] = true;
        // check the number of segments in the token
        if (count($data) != 3) {
            try {
                throw new Exception('Wrong number of segments');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'segments';
                $error = Base::ArrayToObj($error);
                return $error;
            }
        }
        list($head_64, $body_64, $crypto_64) = $data;
        // decode the first segment
        $head_raw = static::base64Decode($head_64);
        if ($head_raw === false || null === ($header = static::jsonDecode($head_raw))){
            try {
                throw new Exception('Invalid header encoding');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'header';
                $error = Base::ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "JWT Header decoded, alg=".($header->alg ?? '(none)');
        // decode the second segment
        $body_raw = static::base64Decode($body_64);
        if ($body_raw === false || null === ($payload = static::jsonDecode($body_raw))) {
            try {
                throw new Exception('Invalid claims encoding');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'payload';
                $error = Base::ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "JWT Payload decoded (contents not logged for privacy)";
        // decode the signature
        if (false === ($signature = static::base64Decode($crypto_64))) {
            try {
                throw new Exception('Invalid signature encoding');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'signature';
                $error = Base::ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "JWT Signature decoded, length=".static::safeStr_len($signature);
        // check that the encryption algorithm info is present and is in the whitelist.
        // This prevents an "alg confusion" attack — the token cannot dictate to the server
        // which algorithm to verify itself with, unless that algorithm is explicitly allowed.
        if (empty($header->alg) || !isset(static::$allowed_algs[$header->alg])) {
            try {
                throw new Exception('Empty or unsupported algorithm');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'alg';
                $error = Base::ArrayToObj($error);
                return $error;
            }
        }
        // the encryption key is mandatory for signature verification
        if (!is_string($security) || $security === '') {
            $this->logs[] = 'Session decodeJWT Error: Security key is required';
            if ($this->debug) $this->logs[] = "Decode JWT: STOP";
            $error['info'] = 'Security key is required';
            $error['case'] = 'security';
            $error = Base::ArrayToObj($error);
            return $error;
        }
        // verify the signature using the hash algorithm that matches header->alg (not a hardcoded one)
        if (!static::verify("$head_64.$body_64", $signature, $security, static::$allowed_algs[$header->alg])) {
            try {
                throw new Exception('Signature verification failed');
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'signature check';
                $error = Base::ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "JWT signature verified";
        // check the nbf claim
        // nbf: Unix Time defining the moment the token becomes valid (not before).
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
                $error['time'] = $payload->nbf;
                $error = Base::ArrayToObj($error);
                return $error;
            }
        }
        // check the iat claim
        // iat: Unix Time defining the moment the token was issued.
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
                $error['time'] = $payload->iat;
                $error = Base::ArrayToObj($error);
                return $error;
            }
        }
        // check the exp claim
        // exp: Unix Time defining the moment the token expires.
        // Check if this token has expired.
        if (isset($payload->exp) && ($timestamp - $leeway) >= $payload->exp) {
            try {
                throw new Exception('Expired token. Cannot handle token after ' . date(DateTime::ISO8601, $payload->exp));
            }
            catch (Exception $e) {
                $this->logs[] = 'Session decodeJWT Error: '.$e->getMessage();
                if ($this->debug) $this->logs[] = "Decode JWT: STOP";
                $error['info'] = $e->getMessage();
                $error['case'] = 'exp';
                $error['time'] = $payload->exp;
                $error = Base::ArrayToObj($error);
                return $error;
            }
        }
        if ($this->debug) $this->logs[] = "Decode JWT: STOP";
        return $payload;
    }

    /**
     * Retrieve data from the token header and body regardless of the signature.
     * Used, for example, to obtain the ID of a compromised client.
     * @param $jwt - the token
     * @return array
     */
    public function getJWTData ($jwt) {
        if ($this->debug) $this->logs[] = "Get JWT Data: START";
        $data = explode('.', $jwt);
        $result = array();
        if (count($data) > 2) {
            @list($head_64, $body_64, $crypto_64) = $data;
            unset($crypto_64);
            $head_raw = static::base64Decode($head_64);
            $body_raw = static::base64Decode($body_64);
            $header = ($head_raw === false) ? null : static::jsonDecode($head_raw);
            $payload = ($body_raw === false) ? null : static::jsonDecode($body_raw);
            if (is_object($header) && !empty($header->alg)) $result['header'] = (array) $header;
            if ($payload !== null) $result['payload'] = Base::ObjToArray($payload);
        }
        // Do not log the raw token or the payload/header contents even in debug mode —
        // this may be sensitive user information.
        if ($this->debug) $this->logs[] = "Get JWT Data: parsed=".(count($result) ? 'yes' : 'no');
        if ($this->debug) $this->logs[] = "Get JWT Data: STOP";
        return $result;
    }

    /**
     * Signature verification
     * @param string $msg - the data being transmitted (header and body of the token)
     * @param string $signature - the signature
     * @param string $key - encryption key
     * @param string $alg - hash algorithm
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
     * JSON decoding
     * @param string $input - json string
     * @param boolean $assoc - whether to return an associative array or not
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
     * JSON encoding
     * @param array $input - data array
     * @return false|string
     */
    public static function jsonEncode($input) {
        $json = json_encode($input, JSON_FORCE_OBJECT | JSON_NUMERIC_CHECK | JSON_UNESCAPED_UNICODE);
        return $json;
    }

    /**
     * Encoding to URLBase64 format
     * @param string $input - data string
     * @return mixed
     */
    public static function base64Encode ($input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Decoding from URLBase64 format
     * @param string $input - string in Base64 URL format
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
     * Generate the signature for a JWT token
     * @param string $input - the string to sign
     * @param string $key - encryption key
     * @param string $alg - hash algorithm
     * @return mixed
     */
    public static function getSignature ($input, $key, $alg = 'sha256') {
        return static::base64Encode(hash_hmac($alg, $input, $key, true));
    }

    /**
     * Calculate string length
     * @param string $str - the string
     * @return int
     */
    private static function safeStr_len($str) {
        if (function_exists('mb_strlen')) return mb_strlen($str, '8bit');
        return strlen($str);
    }

    /**
     * Save the JWT in a browser cookie
     * @param array $data - user data
     * @param string $key - encryption key
     * @param array $header - headers
     * @param string $cookie_name - cookie name
     * @param bool $hash - store an md5 hash of the key in the cookie
     * @return mixed
     */
    public function setJWT ($data, $key, $header = array(), $cookie_name = '', $hash = false) {
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
        // The encryption key is mandatory and must be provided explicitly by the calling code.
        // Previously, when $key === null, the value of $header['alg'] (e.g. "HS256") was used
        // instead, which turned the secret into a predictable public string — this was a
        // security vulnerability.
        if (!is_string($key) || $key === '') {
            $this->logs[] = "Set JWT Error: Security key is required";
            if ($this->debug) $this->logs[] = "Set JWT: STOP";
            return false;
        }
        $jwt = static::createJWT($header, $data, $key);
        if ($jwt === false) {
            $this->logs[] = "Set JWT Error: token generation failed";
            if ($this->debug) $this->logs[] = "Set JWT: STOP";
            return false;
        }
        // The cookie domain should ideally be set explicitly via the application configuration
        // rather than relying on SERVER_NAME (which may depend on the Host header, potentially
        // controllable by the client if the web server/vhost is misconfigured).
        $domain = (SERVER_NAME != 'localhost' && preg_match("/\./", SERVER_NAME))?SERVER_NAME:false;
        if ($this->debug) $this->logs[] = 'Session domain for JWT: '.$domain;
        if ($hash) setcookie($cookie_name, Base::getKeyHash($jwt), array('expires'=>$exp, 'path'=>'/', 'domain'=>$domain, 'secure'=>$this->secure, 'httponly'=>$this->http_only, 'samesite'=>$this->samesite));
        else setcookie($cookie_name, $jwt, array('expires'=>$exp, 'path'=>'/', 'domain'=>$domain, 'secure'=>$this->secure, 'httponly'=>$this->http_only, 'samesite'=>$this->samesite));
        if ($this->debug) $this->logs[] = "Set JWT: STOP";
        return $jwt;
    }

    /**
     * Verify the JWT token and return the data
     * @param string $jwt - JWT string
     * @param string $security - encryption key
     * @param null $timestamp - fixed token lifetime timestamp, optional parameter. Defaults to time()
     * @param int $leeway - additional token lifetime allowance to account for clock skew.
     * @return bool|object
     * @throws Exception
     */
    public function checkJWT ($jwt, $security = '', $timestamp = null, $leeway = 0) {
        if ($this->debug) $this->logs[] = "Check JWT: START";
        $data = static::decodeJWT($jwt, $security, $timestamp, $leeway);
        /* ToDo check
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
        if ($this->debug) $this->logs[] = "Check JWT: data returned (contents not logged for privacy), is_error=".(isset($data->error) && $data->error ? 'true' : 'false');
        if ($this->debug) $this->logs[] = "Check JWT: STOP";
        return $data;
    }

    /**
     * Clear the keys
     * @return bool
     */
    public function clearJWT ($cookie_name = 'token') {
        if ($this->debug) $this->logs[] = "Clear JWT: START";
        $domain = (SERVER_NAME != 'localhost' && preg_match("/\./", SERVER_NAME))?SERVER_NAME:false;
        if (!$cookie_name && $this->token_cookie_name) $cookie_name = $this->token_cookie_name;
        if (isset($_COOKIE[$cookie_name])) {
            $param = array(
                'expires'=>time()-1, 
                'path'=>'/', 
                'domain'=>$domain, 
                'secure'=>$this->secure, 
                'httponly'=>$this->http_only, 
                'samesite'=>$this->samesite
            );
            setcookie($cookie_name, '', $param);
            unset($_COOKIE[$cookie_name]);
            // old version for BNB
            if (isset($_COOKIE['refresh_token'])) setcookie('refresh_token', '', $param);
            if (isset($_COOKIE['API'])) setcookie('API', '', $param);
            if (isset($_COOKIE['API_R'])) setcookie('API_R', '', $param);
            unset($_COOKIE['refresh_token'], $_COOKIE['API'], $_COOKIE['API_R']);
            //
            if ($this->debug) $this->logs[] = "JWT deleted from cookie";
            if ($this->debug) $this->logs[] = "Clear JWT: STOP";
            return true;
        }
        else {
            if ($this->debug) $this->logs[] = "Warning! JWT cookie not found";
            if ($this->debug) $this->logs[] = "Clear JWT: STOP";
            return false;
        }
    }

    /**
     * Returns the logs
     * @return array
     */
    public function getLogs () {
        $return['log'] = $this->logs;
        $return['file'] = $this->log_file;
        return $return;
    }
}
