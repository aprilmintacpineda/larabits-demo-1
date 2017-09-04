<?php
session_start();

if(!empty($_POST)) {
  /*
   * error checking first
   * must have a token
   * must be the same as stored on the session
   * must pass user input validations
   * must pass credential validations
   */
  
  // list of wanted fields
  $fields = [
    'user_email',
    'user_password',
    'confirm_password',
    'full_name',
    'token'
  ];

  $errors = [];

  if(!isset($_POST['token']) || $_POST['token'] != $_SESSION['token'] || array_keys($_POST) != $fields) {
    // token is invalid or a field is missing or was injected.
    $errors['critical_error'] = 'Sorry, we could not validate the form you just submitted.';
  } else {
    // validate user inputs
    
    /*
     * email validations
     * Email must be a valid email
     * Email must not be empty
     * Email must not be already taken
     */
    if(empty($_POST['user_email'])) {
      $errors['user_email'][] = 'Email is required.';
    } else {
      if(!filter_var($_POST['user_email'], FILTER_VALIDATE_EMAIL)) {
        $errors['user_email'][] = 'Invalid email.';
      }

      // check if email is already taken as well.
    }

    /*
     * password validations
     * password must not be empty
     * confirm password must not be empty
     * password must equal confirm password
     */
    if(empty($_POST['user_password'])) {
      $errors['user_password'][] = 'Password is required';
    }

    if(empty($_POST['confirm_password'])) {
      $errors['confirm_password'][] = 'Retype your password.';
    } else if(!empty($_POST['user_password']) && $_POST['user_password'] != $_POST['confirm_password']) {
      $errors['confirm_password'][] = 'Passwords did not matched.';
    }

    /*
     * full name validations
     * full name must not be empty
     * full name must be alphabet only
     * full name must be less than or equal to 100 chars
     */
    if(empty($_POST['full_name'])) {
      $errors['full_name'][] = 'Full name is required.';
    } else {
      if(strlen($_POST['full_name']) > 100) {
        $errors['full_name'][] = 'Full name must not exceed 100 characters.';
      }

      if(!preg_match('/^[a-zA-Z\'?\-?\.? ]+$/', 'April Mintac Pineda')) {
        $errors['full_name'][] = 'Invalid full name.';
      }
    }

    if(empty($errors)) {
      // hash password
      // sanitize full name
      // connect to database
      // insert data
      $registered = true;
    }
  }
}

// acts as a CSRF protection
$token = str_shuffle('0123456789abcdefghijklmnopqrstuvwxyz9876543210ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
$_SESSION['token'] = $token;
?>
<!DOCTYPE html>
<html>
<head>
  <title>My Awesome Site</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" type="text/css" href="./css/my-awesome-design.css">
</head>
<body>
  <div class="form-wrapper">
    <h1>My Awesome Website</h1>

    <form method="post" action="">
    <ul>
      <li>
        <p>Your email</p>
        <?= isset($errors, $errors['user_email']) && !empty($errors['user_email'])? '<p class="error">' . implode('</p><p class="error">', $errors['user_email']) . '</p>' : '' ?>
        <input type="email" name="user_email" placeholder="example@domain.com" value="<?= !empty($_POST) && !isset($errors['critical_error'])? $_POST['user_email'] : '' ?>">
      </li>
      <li>
        <p>Desired password</p>
        <?= isset($errors, $errors['user_password']) && !empty($errors['user_password'])? '<p class="error">' . implode('</p><p class="error">', $errors['user_password']) . '</p>' : '' ?>
        <input type="password" name="user_password" placeholder="my secret and strong password!">
      </li>
      <li>
        <p>Confirm password</p>
        <?= isset($errors, $errors['confirm_password']) && !empty($errors['confirm_password'])? '<p class="error">' . implode('</p><p class="error">', $errors['confirm_password']) . '</p>' : '' ?>
        <input type="password" name="confirm_password" placeholder="my secret and strong password!">
      </li>
      <li>
        <p>Full name</p>
        <?= isset($errors, $errors['full_name']) && !empty($errors['full_name'])? '<p class="error">' . implode('</p><p class="error">', $errors['full_name']) . '</p>' : '' ?>
        <input type="text" name="full_name" placeholder="April Mintac Pineda" maxlength="100" value="<?= !empty($_POST) && !isset($errors['critical_error'])? $_POST['full_name'] : '' ?>">
      </li>
      <li>
        <?=
          isset($errors, $errors['critical_error']) && !empty($errors['critical_error'])? '<p class="error">'. $errors['critical_error'] .'</p>'
          : isset($registered) && $registered? '<p class="success">Hooray! You have been registered.</p>'
          : ''
        ?>
        <input type="submit" value="Create account">
      </li>
    </ul>
    <input type="hidden" name="token" value="<?= $token ?>">
  </form>
  </div>
</body>
</html>