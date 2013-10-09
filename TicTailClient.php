<?php
/**
  *  The MIT License (MIT)
  *
  *  Copyright (c) 2013 Actual Reports
  *
  *  Permission is hereby granted, free of charge, to any person obtaining a copy of
  *  this software and associated documentation files (the "Software"), to deal in
  *  the Software without restriction, including without limitation the rights to
  *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
  *  the Software, and to permit persons to whom the Software is furnished to do so,
  *  subject to the following conditions:
  *
  *  The above copyright notice and this permission notice shall be included in all
  *  copies or substantial portions of the Software.
  *
  *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
  *  FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
  *  COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
  *  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  *
  **/

class TicTailException extends Exception {}

class TicTailClient
{
  const ERROR_CODE_OUTDATED = 1;
  const ERROR_CURL = 2;
  const ERROR_REQUEST = 3;

  private $authUrl = 'https://tictail.com/oauth/';
  private $apiUrl = 'https://api.tictail.com';
  private $code;
  private $clientId;
  private $clientSecret;
  private $data;
  private $info;

  private $token;
  private $expires;
  private $storeData;
  private $storeId;

  /**
   * Constructor
   *
   * @param string $clientId
   * @param string $clientSecret
   * @param string $token
   */
  public function __construct($clientId, $clientSecret, $token = null)
  {
    $this->clientId = $clientId;
    $this->clientSecret = $clientSecret;
    if ($token)
    {
      $this->token = $token;
    }
  }

  /**
   * Authenticates user with given code
   *
   * @param string $code
   * @return string
   */
  public function authenticate($code)
  {
    if (!$this->token || $this->code != $code || time() > $this->expires)
    {
      if (!$this->clientId)
      {
        throw new TicTailException('Missing $this->clientId');
      }
      else if (!$this->clientSecret)
      {
        throw new TicTailException('Missing $this->clientSecret');
      }
      $this->code = $code;
      $this->refreshAuthToken($code);
    }

    return $this->token;
  }

  /**
   * Returns url to reauthorize the user
   *
   * @param string $redirectUrl
   * @return string
   */
  public function getAuthorizeUrl($code, $redirectUrl)
  {
    return $this->authUrl.'authorize?response_type='.$code.'&client_id='.$this->clientId.'&redirect_uri='.$redirectUrl;
  }

  /**
   * Returns current auth token
   * @return string
   */
  public function getAccessToken()
  {
    return $this->token;
  }

  /**
   * Set token and auth expire time
   *
   * @param string $token
   * @param integer $expires timestamp
   */
  public function setAccessToken($token, $expires = null)
  {
    $this->token = $token;
    $this->expires = $expires ? $expires : time();
  }

  /**
   * Returns store data collected from authentication call
   *
   * @return array
   */
  public function getStoreData()
  {
    return $this->storeData;
  }

  /**
   * Returns store unique id
   *
   * @return string
   */
  public function getStoreId()
  {
    return $this->storeId;
  }

  /**
   * Call resource
   *
   * @param string $method POST or GET
   * @param string $path to resource
   * @param array $params
   *
   * @return array
   */
  public function call($method, $path, $params = array())
  {
    return $this->makeCurlRequest($method, $this->apiUrl.$path, $params, array(
      'Authorization: Bearer '.$this->token
    ));
  }

  /**
   * Refresh auth token from server
   *
   * @param string $code
   */
  private function refreshAuthToken($code)
  {
    $payload = array(
      'client_id' => $this->clientId,
      'client_secret' => $this->clientSecret,
      'code' => $code,
      'grant_type' => 'authorization_code'
    );

    $response = $this->makeCurlRequest('POST', $this->authUrl.'token', $payload);
    $this->token = $response['access_token'];
    $this->expires = time() + $response['expires_in'];
    $this->storeData = $response['store'];
    $this->storeId = $this->storeData['id'];
  }

  private function makeCurlRequest($method, $url, $payload = array(), $headers = array())
  {
    if ($method == 'GET' && is_array($payload) && !empty($payload))
    {
      $url .= '?'.http_build_query($payload);
    }
    $ch = curl_init($url);
    $this->curlSetopts($ch, $method, $payload, $headers);
    $response = curl_exec($ch);
    list($messageHeaders, $messageBody) = preg_split("/\r\n\r\n|\n\n|\r\r/", $response, 2);

    if ($messageBody === false || $messageBody === null) {
      $errorCode = curl_errno($ch);
      $error = curl_error($ch);
      throw new TicTailException($error.'(Code: '.$errorCode.')', self::ERROR_CURL);
    } else {
      $this->info = curl_getinfo($ch);
    }

    curl_close($ch);

    $this->data = json_decode($messageBody, true);

    if ($this->info['http_code'] != 200)
    {
      $error = self::ERROR_CODE_OUTDATED;
      $message = "Reauthorize the user!";

      if (isset($this->data['message']))
      {
        $message = $this->data['message'];
        $error = self::ERROR_REQUEST;
      }
      if (isset($this->data['error']))
      {
        $message = $this->data['error'];
        $error = self::ERROR_REQUEST;
      }
      throw new TicTailException($message, $error);
    }

    return $this->data;
  }

  private function curlSetopts($ch, $method, $payload, $headers)
  {
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_USERAGENT, 'HAC');
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLINFO_HEADER_OUT, true);

    curl_setopt ($ch, CURLOPT_CUSTOMREQUEST, $method);

    if (!empty($headers))
    {
      curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }

    if ($method != 'GET' && !empty($payload))
    {
      if (is_array($payload))
      {
        $payload = http_build_query($payload);
      }
      curl_setopt ($ch, CURLOPT_POSTFIELDS, $payload);
    }
  }
}