const assert = require('assert');
const mongoose = require('mongoose');
const UserModel = require('./UserModel');

const DB_URL = 'mongodb://localhost:27017/password';
const USERNAME = `${Math.random()}`;
let password = 123456;

describe('Test Database', () => {

  before(function(done) {
    mongoose.Promise = global.Promise;
    mongoose.connect(DB_URL, {
      useMongoClient: true,
      reconnectTries: Number.MAX_VALUE,
      reconnectInterval: 4000
    });

    const db = mongoose.connection;
    db.on('error', () => {
      throw new Error('Cannot connect to db!');
    });
    db.once('open', () => {
      UserModel.create({
        username: USERNAME
      }).then(() => done());
    });
  });

  describe('# reset password()', () => {
    it('first time set password', function (done) {
      UserModel.resetPassword(USERNAME, password)
        .then(() => done())
        .catch(done);
    });

    it('reset password should throw too soon', function (done) {
      UserModel.resetPassword(USERNAME, password)
        .then(() => done('should throw'))
        .catch(err => {
          if (err === 'resetTooSoon') done();
          else done(err);
        });
    });

    it('reset password should success after 1s', function (done) {
      setTimeout(() => {
        UserModel.resetPassword(USERNAME, ++password)
          .then(() => done())
          .catch(done);
        }, 1000);
    });

    it('reset password should throw noPreviousPassword', function (done) {
      setTimeout(() => {
        UserModel.resetPassword(USERNAME, password - 1)
          .then(() => done('should throw'))
          .catch(err => {
            if (err === 'noPreviousPassword') done();
            else done(err);
          });
        }, 1000);
    });
  });


  describe('# login()', () => {
    it('incorrect password', function (done) {
      UserModel.loginByPassword(USERNAME, password - 1)
        .then(() => done('should throw'))
        .catch(err => {
          if (err === 'incorrect') done();
          else done(err);
        });
    });

    it('login to soon wrong password', function (done) {
      UserModel.loginByPassword(USERNAME, password - 1)
        .then(() => done('should throw'))
        .catch(err => {
          if (err === 'attemptedTooSoon') done();
          else done(err);
        });
    });

    it('login to soon right password', function (done) {
      UserModel.loginByPassword(USERNAME, password)
        .then(() => done('should throw'))
        .catch(err => {
          if (err === 'attemptedTooSoon') done();
          else done(err);
        });
    });

    it('login attempt too many', function (done) {
      setTimeout(() => {
        UserModel.loginByPassword(USERNAME, password)
          .then(() => done('should throw'))
          .catch(err => {
            if (err === 'attemptedTooMany') done();
            else done(err);
          });
        }, 1000);
    });

    it('reset password should success after 1s', function (done) {
      setTimeout(() => {
        UserModel.resetPassword(USERNAME, ++password)
          .then(() => done())
          .catch(done);
        }, 1000);
    });

    it('login success', function (done) {
      setTimeout(() => {
        UserModel.loginByPassword(USERNAME, password)
          .then(() => done())
          .catch(done);
        }, 1000);
    });

    it('password expired', function (done) {
      this.timeout(5000);

      setTimeout(() => {
        UserModel.loginByPassword(USERNAME, password)
          .then(() => done('should throw'))
          .catch(err => {
            if (err === 'expired') done();
            else done(err);
          });
        }, 4000);
    });
  });
});
