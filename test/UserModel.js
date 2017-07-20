const passwordMongoose = require('../index');
const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const passwordConfig = {
  passwordField: 'password',
  archiveField: 'passwordArchive',
  usernameField: 'username',
  iterate: 3,
  noPreviousCount: 2,
  maxAttempts: 3,
  minAttemptInterval: 1000,
  minResetInterval: 1000,
  expiration: 5000,
  backdoorKey: 'abc1234B',
  errors: {
    dbError: 'dbError',
    userNotFound: 'userNotFound',
    notSet: 'notSet',
    incorrect: 'incorrect',
    expired: 'expired',
    resetTooSoon: 'resetTooSoon',
    noPreviousPassword: 'noPreviousPassword',
    attemptedTooSoon: 'attemptedTooSoon',
    attemptedTooMany: 'attemptedTooMany'
  }
};

const UserSchema = new Schema({
  username: {
    type: String,
    required: true
  }
});

UserSchema.plugin(passwordMongoose, passwordConfig);

module.exports = mongoose.model('users', UserSchema);
