<?php
/*
Plugin Name: Nextend Google Connect
Plugin URI: http://nextendweb.com/
Description: Google connect
Version: 1.4.11
Author: Roland Soos
License: GPL2
*/

/*  Copyright 2012  Roland Soos - Nextend  (email : roland@nextendweb.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

define( 'NEW_GOOGLE_LOGIN', 1 );
if ( ! defined( 'NEW_GOOGLE_LOGIN_PLUGIN_BASENAME' ) )
	define( 'NEW_GOOGLE_LOGIN_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
  
$new_google_settings = maybe_unserialize(get_option('nextend_google_connect'));

/*
  Sessions required for the profile notices 
*/
function new_google_start_session() {
  if(!session_id()) {
      session_start();
  }
}

function new_google_end_session() {
  session_destroy ();
}

add_action('init', 'new_google_start_session', 1);
add_action('wp_logout', 'new_google_end_session');
add_action('wp_login', 'new_google_end_session');

/*
  Loading style for buttons
*/
function nextend_google_connect_stylesheet(){
  wp_register_style( 'nextend_google_connect_stylesheet', plugins_url('buttons/google-btn.css', __FILE__) );
  wp_enqueue_style( 'nextend_google_connect_stylesheet' );
}

if($new_google_settings['google_load_style']){
  add_action( 'wp_enqueue_scripts', 'nextend_google_connect_stylesheet' );
  add_action( 'login_enqueue_scripts', 'nextend_google_connect_stylesheet' );
  add_action( 'admin_enqueue_scripts', 'nextend_google_connect_stylesheet' );
}

/*
  Creating the required table on installation
*/
function new_google_connect_install(){
  global $wpdb;
  
  $table_name = $wpdb->prefix . "social_users";
    
  $sql = "CREATE TABLE $table_name (
    `ID` int(11) NOT NULL,
    `type` varchar(20) NOT NULL,
    `identifier` varchar(100) NOT NULL,
    KEY `ID` (`ID`,`type`)
  );";

   require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
   dbDelta($sql);
}
register_activation_hook(__FILE__, 'new_google_connect_install');

/*
  Adding query vars for the WP parser
*/
function new_google_add_query_var(){
  global $wp;
  $wp->add_query_var('editProfileRedirect');
  $wp->add_query_var('loginGoogle');
}
add_filter('init', 'new_google_add_query_var');

/* -----------------------------------------------------------------------------
  Main function to handle the Sign in/Register/Linking process
----------------------------------------------------------------------------- */
function new_google_login(){
  global $wp, $wpdb, $new_google_settings;
  if($wp->request == 'loginGoogle' || isset($wp->query_vars['loginGoogle'])){
    include(dirname(__FILE__).'/sdk/init.php');
    if (isset($_GET['code'])) {
      $client->authenticate();
      $_SESSION['token'] = $client->getAccessToken();
      $redirect = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
      header('Location: ' . filter_var(new_google_login_url(), FILTER_SANITIZE_URL));
      exit;
    }
    
    if (isset($_SESSION['token'])) {
     $client->setAccessToken($_SESSION['token']);
    }
    
    if (isset($_REQUEST['logout'])) {
      unset($_SESSION['token']);
      $client->revokeToken();
    }
    
    if ($client->getAccessToken()) {
      $u = $oauth2->userinfo->get();
      // The access token may have been updated lazily.
      $_SESSION['token'] = $client->getAccessToken();
    
      // These fields are currently filtered through the PHP sanitize filters.
      // See http://www.php.net/manual/en/filter.filters.sanitize.php
      $email = filter_var($u['email'], FILTER_SANITIZE_EMAIL);
      
      $ID = $wpdb->get_var($wpdb->prepare('
        SELECT ID FROM '.$wpdb->prefix.'social_users WHERE type = "google" AND identifier = "'.$u['id'].'"
      '));
      if(!get_user_by('id',$ID)){
        $wpdb->query($wpdb->prepare('
          DELETE FROM '.$wpdb->prefix.'social_users WHERE ID = "'.$ID.'"
        '));
        $ID = null;
      }
      if(!is_user_logged_in()){
        if($ID == NULL){ // Register
          $ID = email_exists($email);
          if($ID == false){ // Real register
            require_once( ABSPATH . WPINC . '/registration.php');
            $random_password = wp_generate_password( $length=12, $include_standard_special_chars=false );
            $settings = $new_google_settings;
              
            if(!isset($settings['google_user_prefix'])) $settings['google_user_prefix'] = 'Google - ';
              
            $ID = wp_create_user( $settings['google_user_prefix'].$u['name'], $random_password, $email );
            wp_update_user(array(
              'ID' => $ID, 
              'display_name' => $u['name'], 
              'first_name' => $u['given_name'], 
              'last_name' => $u['family_name'], 
              'googleplus' => $u['link']
            ));
          }
          $wpdb->insert( 
          	$wpdb->prefix.'social_users', 
          	array( 
          		'ID' => $ID, 
          		'type' => 'google',
              'identifier' => $u['id']
          	), 
          	array( 
          		'%d', 
          		'%s',
              '%s'
          	)
          );
        }
        if($ID){ // Login
          wp_set_auth_cookie($ID, true, false);
          do_action('wp_login', $settings['google_user_prefix'].$u['name']);
          header( 'Location: '.$_SESSION['redirect'] );
          unset($_SESSION['redirect']);
          exit;
        }
      }else{
        $current_user = wp_get_current_user();
        if($current_user->ID == $ID){ // It was a simple login
          header( 'Location: '.$_SESSION['redirect'] );
          unset($_SESSION['redirect']);
          exit;
        }elseif($ID === NULL){  // Let's connect the accout to the current user!
          $wpdb->insert( 
          	$wpdb->prefix.'social_users', 
          	array( 
          		'ID' => $current_user->ID, 
          		'type' => 'google',
              'identifier' => $u['id']
          	), 
          	array( 
          		'%d', 
          		'%s',
              '%s'
          	) 
          );
          $_SESSION['new_google_admin_notice'] = __('Your Google profile is successfully linked with your account. Now you can sign in with Google easily.', 'nextend-google-connect');
          header( 'Location: '.(isset($_SESSION['redirect']) ? $_SESSION['redirect'] : $_GET['redirect']) );
          unset($_SESSION['redirect']);
          exit;
        }else{
          $_SESSION['new_google_admin_notice'] = __('This Google profile is already linked with other account. Linking process failed!', 'nextend-google-connect');
          header( 'Location: '.(isset($_SESSION['redirect']) ? $_SESSION['redirect'] : $_GET['redirect']) );
          unset($_SESSION['redirect']);
          exit;
        }
      }
    } else {
      if(isset($new_google_settings['google_redirect']) && $new_google_settings['google_redirect'] != '' && $new_google_settings['google_redirect'] != 'auto'){
        $_GET['redirect'] = $new_google_settings['google_redirect'];
      }
      $_SESSION['redirect'] = isset($_GET['redirect']) ? $_GET['redirect'] : site_url();
      header('LOCATION: '.$client->createAuthUrl());
      exit;
    }
    exit;
  }
}
add_action('parse_request', new_google_login);

/*
  Is the current user connected the Google profile? 
*/
function new_google_is_user_connected(){
  global $wpdb;
  $current_user = wp_get_current_user();
  $ID = $wpdb->get_var($wpdb->prepare('
    SELECT ID FROM '.$wpdb->prefix.'social_users WHERE type = "google" AND ID = "'.$current_user->ID.'"
  '));
  if($ID === NULL) return false;
  return true;
}

/*
  Connect Field in the Profile page
*/
function new_add_google_connect_field() {
  global $new_is_social_header;
  if($new_is_social_header === NULL){
    ?>
    <h3>Social connect</h3>
    <?php
    $new_is_social_header = true;
  }
  ?>
  <table class="form-table">
    <tbody>
      <tr>	
        <th></th>	
        <td>
          <?php if(!new_google_is_user_connected()): ?>
            <?php echo new_google_link_button() ?>
          <?php endif; ?>
        </td>
      </tr>
    </tbody>
  </table>
  <?php
}
add_action('profile_personal_options', 'new_add_google_connect_field');

function new_add_google_login_form(){
  ?>
  <script>
  if(jQuery.type(has_social_form) === "undefined"){
    var has_social_form = false;
    var socialLogins = null;
  }
  jQuery(document).ready(function(){
    (function($) {
      if(!has_social_form){
        has_social_form = true;
        var loginForm = $('#loginform');
        socialLogins = $('<div class="newsociallogins" style="text-align: center;"><div style="clear:both;"></div></div>');
        loginForm.prepend("<h3 style='text-align:center;'>OR</h3>");
        loginForm.prepend(socialLogins);
      }
      socialLogins.prepend('<?php echo addslashes(preg_replace('/^\s+|\n|\r|\s+$/m', '',new_google_sign_button())); ?>');
    }(jQuery));
  });
  </script>
  <?php
}

add_action('login_form', 'new_add_google_login_form');

/* 
  Options Page 
*/
require_once(trailingslashit(dirname(__FILE__)) . "nextend-google-settings.php");

if(class_exists('NextendGoogleSettings')) {
	$nextendgooglesettings = new NextendGoogleSettings();
	
	if(isset($nextendgooglesettings)) {
		add_action('admin_menu', array(&$nextendgooglesettings, 'NextendGoogle_Menu'), 1);
	}
}

add_filter( 'plugin_action_links', 'new_google_plugin_action_links', 10, 2 );

function new_google_plugin_action_links( $links, $file ) {
  if ( $file != NEW_GOOGLE_LOGIN_PLUGIN_BASENAME )
  	return $links;
	$settings_link = '<a href="' . menu_page_url( 'nextend-google-connect', false ) . '">'
		. esc_html( __( 'Settings', 'nextend-google-connect' ) ) . '</a>';

	array_unshift( $links, $settings_link );

	return $links;
}


/* -----------------------------------------------------------------------------
  Miscellaneous functions
----------------------------------------------------------------------------- */
function new_google_sign_button(){
  global $new_google_settings;
  return '<a href="'.new_google_login_url().(isset($_GET['redirect_to']) ? '&redirect='.$_GET['redirect_to'] : '').'" rel="nofollow">'.$new_google_settings['google_login_button'].'</a><br />';
}

function new_google_link_button(){
  global $new_google_settings;
  return '<a href="'.new_fb_login_url().'&redirect='.site_url().$_SERVER["REQUEST_URI"].'">'.$new_google_settings['google_link_button'].'</a><br />';
}

function new_google_login_url(){
  return site_url('index.php').'?loginGoogle=1';
}

function new_google_edit_profile_redirect(){
  global $wp;
  if(isset($wp->query_vars['editProfileRedirect']) ){
    if(function_exists('bp_loggedin_user_domain')){
      header('LOCATION: '.bp_loggedin_user_domain().'profile/edit/group/1/');
    }else{
      header('LOCATION: '.self_admin_url( 'profile.php' ));
    }
    exit;
  }
}
add_action('parse_request', new_google_edit_profile_redirect);

/*
  Session notices used in the profile settings
*/
function new_google_admin_notice(){
  if(isset($_SESSION['new_google_admin_notice'])){
    echo '<div class="updated">
       <p>'.$_SESSION['new_google_admin_notice'].'</p>
    </div>';
    unset($_SESSION['new_google_admin_notice']);
  }
}
add_action('admin_notices', 'new_google_admin_notice');
