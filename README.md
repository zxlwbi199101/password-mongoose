# password-mongoose
password-mongoose is a [Mongoose plugin](http://mongoosejs.com/docs/plugins.html)
that simplifies supporting login / reset password in Promise style api.

## Installation
```bash
  npm install password-mongoose
```
password-mongoose depends on nothing, but you must install mongoose, because it's a mongoose-plugin.

## Usage

### how to plugin to mongoose

When you are defining your schema, call `Model.plugin(plugin, config)` to your model. This will add two fields and two methods to your schema. See the [API](#api) documentation section for more details.

```javascript
  const mongoose = require('mongoose');
  const passwordMongoose = require('password-mongoose');

  const config = {
    passwordField: 'password',
    archiveField: 'passwordArchive',
    usernameField: 'username',
    iterate: 3,
    noPreviousCount: 5, // 0 is never check
    maxAttempts: 10,
    minAttemptInterval: 1000, // 1s
    minResetInterval: 1000, // 1s
    expiration: 90 * 24 * 60 * 60 * 1000, // 90 days
    backdoorKey: null
    errors: {
      dbError: 'Cannot access database',
      userNotFound: 'User not found.',
      notSet: 'You did not set password, please set it first.',
      incorrect: 'Your password is incorrect.',
      expired: 'Your password has been expired, please reset a new one.',
      resetTooSoon: 'You have reset too soon. Try again later.',
      noPreviousPassword: 'You are using previous passwords, try another.',
      attemptedTooSoon: 'You have login too soon. Try again later.',
      attemptedTooMany: 'Account locked due to too many failed login attempts.'
    }
  };

  const User = new mongoose.Schema({
    username: { type: String, required: true }
  });
  User.plugin(passwordMongoose, config);

  module.exports = mongoose.model('User', User);
```

### configuration
```javascript
{
  passwordField: 'password', // field to store password in db
  archiveField: 'passwordArchive', // field to store history in db
  usernameField: 'username', // username field name
  iterate: 3, // encrypt iteration time
  noPreviousCount: 5, // check for duplicate password when reseting password
  maxAttempts: 10, // how many failed login before lock the user
  minAttemptInterval: 1000, // min interval between two login
  minResetInterval: 1000, // min interval between two reset password
  expiration: 90 * 24 * 60 * 60 * 1000, // password expired in
  backdoorKey: null // a backdoor password for debug (null means disabled)
  errors: {
    dbError: 'Cannot access database',
    userNotFound: 'User not found.',
    notSet: 'You did not set password, please set it first.',
    incorrect: 'Your password is incorrect.',
    expired: 'Your password has been expired, please reset a new one.',
    resetTooSoon: 'You have reset too soon. Try again later.',
    noPreviousPassword: 'You are using previous passwords, try another.',
    attemptedTooSoon: 'You have login too soon. Try again later.',
    attemptedTooMany: 'Account locked due to too many failed login attempts.'
  }
}
```
### api

This plugin applies two instance methods: `resetPassword(idOrUsername, password)` and `loginByPassword(username, password)` and two static methods: `resetPassword()` and `loginByPassword(password)` to your schema.

* login:
```javascript
  const User = require('./UserSchema');

  // use instance method
  const user = await User.findOne({ username: 'any_username' });
  const newUser = await user.loginByPassword('password')
    .catch(err => console.log(err));

  // user static method
  const user = await User.loginByPassword('any_username', 'password');
```

* reset password:
```javascript
  const User = require('./UserSchema');

  // use instance method
  const user = await User.findOne({ username: 'any_username' });
  const newUser = await user.resetPassword('password')
    .catch(err => console.log(err));

  // user static method
  const user = await User.resetPassword('any_username', 'password');
```
