<?php
/**
 * OAuth 2.0 MAC Token : Sample Client
 */
include("OAuth2MacTokenClient.php");

// input your client credential
$client_id = "F/XFWBIsbhufw4ICROJVEg==";
$client_secret = "GuCzaTytzuanhpJRUlC8IHt+cg0OOuzsTjFKeZPradA/HT2xRYkWpep+DebUM78qaTJHuxp2FD9A236OuTwjeQ==";
// input your redirect_uri
$redirect_uri = "http://www8322u.sakura.ne.jp/php-OAuth2MacToken/example/client.php";

$authz_endpoint = "http://rack-oauth2-sample-mac.heroku.com/oauth2/authorize";
$token_endpoint = "http://rack-oauth2-sample-mac.heroku.com/oauth2/token";
$resource_endpoint = "http://rack-oauth2-sample-mac.heroku.com/protected_resources";

session_name("o2mac_sample");
session_start();

if (isset($_GET['clear']) && $_GET['clear'] == 1) {
    $_SESSION = array();
    // session_destroy();
}

$authz_link = null;
$code = @$_GET["code"];
if (empty($code) && $_SESSION['state'] == 1)
    $_SESSION['state'] = 0;

$client = new OAuth2MacTokenClient($client_id, $client_secret, $redirect_uri);
try {

    if (empty($code) && !$_SESSION['state'] || $_SESSION['state'] == 0) {

        $authz_link = $client->getRequestAuthUrl($authz_endpoint);
        $_SESSION['state'] = 1;
    } else {

        if ($_SESSION['state'] == 1) {
            $access_token_info = $client->getAccessToken($token_endpoint, $code);
            $token_req = $client->getLastRequestHeader();
            $token_res = $client->getLastResponse();
            $_SESSION['state'] = 2;
            $_SESSION['atoken'] = $access_token_info->access_token;
            $_SESSION['secret'] = $access_token_info->secret;
            $_SESSION['rtoken'] = $access_token_info->refresh_token;
            $_SESSION['algorithm'] = $access_token_info->algorithm;
        }

        if (isset($_GET['refresh']) && $_GET['refresh'] == 1) {
            // refresh Access Token
            $access_token_info = $client->refreshAccessToken($token_endpoint, $_SESSION['rtoken']);
            $token_req = $client->getLastRequestHeader();
            $token_res = $client->getLastResponse();
            if (isset($access_token_info->access_token)) {
                $_SESSION['atoken'] = $access_token_info->access_token;
                $_SESSION['secret'] = $access_token_info->secret;
                $_SESSION['algorithm'] = $access_token_info->algorithm;
            } else {
                $_SESSION = array();
                header("Location : ./client.php");
            }
        }

        // Resource Access
        $method = "GET";
        $client->setMacTokenCredential($_SESSION['atoken'], $_SESSION['secret'], $_SESSION['algorithm']);
        $client->enableResponseHeader(); // for debug
        $client->sendRequest($method, $resource_endpoint);
        $send_header = $client->getLastRequestHeader();
        $res = $client->getLastResponse();
    }
} catch (OAuthException $E) {
    print_r($E);
}
?>
<html>
    <head>
        <title>OAuth 2.0 MAC Token : Sample Client</title>
    </head>
    <body>
        <h1>OAuth 2.0 MAC Token : Sample Client</h1>

        <pre>
This is OAuth 2.0 Sample Client.
AuthZServer : Rack::OAuth2 Sample Server (MAC) by @nov
        </pre>

        <?php if (!empty($authz_link)) {
        ?>

            <a href="<?php echo $authz_link; ?>">start Authorization</a>

        <?php } else {
        ?>
            <a href="./client.php">Reload</a>
            <!--<a href="./client.php?refresh=1">Access Token Refresh</a>-->
            <a href="./client.php?clear=1">Restart</a>

            <h2>Obtain Access Token</h2>
            <h3>Request : </h3>
            <pre><?php echo htmlspecialchars(@$token_req); ?></pre>
            <h3>Response : </h3>
            <pre><?php echo htmlspecialchars(@$token_res); ?></pre>

            <h2>Resource Access</h2>
            <h3>Request : </h3>
            <pre><?php echo htmlspecialchars(@$send_header); ?></pre>
            <h3>Response : </h3>
            <pre><?php echo htmlspecialchars(@$res); ?></pre>

        <?php } ?>
        <hr>
    <footer>
        <small class="copytight">&copy; 2011 <a href="http://github.com/ritou">ritou</a></small>
    </footer>

</body>
</html>