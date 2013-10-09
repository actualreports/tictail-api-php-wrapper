<?php
session_start();
require_once 'TicTailClient.php';

$clientId = ''; // You Client ID
$secret = ''; // Your Client Secret

if (isset($_GET['code']))
{
  $client = new TicTailClient($clientId, $secret);
  try
  {
    // Authenticate user and display store data
    $_SESSION['tictail_token'] = $client->authenticate($_GET['code']);
    header('Location: example.php');
  }
  catch(TicTailException $e)
  {
    die($e->getMessage());
  }
}
else if (isset($_SESSION['tictail_token']))
{
  $client = new TicTailClient($clientId, $secret, $_SESSION['tictail_token']);
  try
  {
    // Print store data
    var_dump($client->call('GET', '/v1/me'));
  }
  catch(TicTailException $e)
  {
    die($e->getMessage());
  }
}

?>