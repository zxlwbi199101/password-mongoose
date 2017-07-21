const crypto = require('crypto');
const mongoose = require('mongoose');

const Types = mongoose.Types;

module.exports = function passwordMongoose (schema, optionsParams = {}) {
  // set default options
  const options = Object.assign({
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
  }, optionsParams);

  const errors = Object.assign({
    dbError: 'Cannot access database',
    userNotFound: 'User not found.',
    notSet: 'You did not set password, please set it first.',
    incorrect: 'Your password is incorrect.',
    expired: 'Your password has been expired, please reset a new one.',
    resetTooSoon: 'You have reset too soon. Try again later.',
    noPreviousPassword: 'You are using previous passwords, try another.',
    attemptedTooSoon: 'You have login too soon. Try again later.',
    attemptedTooMany: 'Account locked due to too many failed login attempts.'
  }, options.errors);

  // append schema
  const schemaFields = {};
  schemaFields[options.passwordField] = {
    hash: { type: String, select: false },
    salt: { type: String, select: false },
    attempts: { type: Number, default: 0, select: false },
    lastAttemptedAt: { type: Date, select: false },
    lastResetAt: { type: Date, select: false }
  };
  schemaFields[options.archiveField] = [{
    hash: { type: String, select: false },
    salt: { type: String, select: false },
    timestamp: { type: Date, default: Date.now, select: false }
  }];
  schema.add(schemaFields);

  function findUserByIdOrUsername (model, idOrUsername) {
    const forceSelect = Object.keys(schemaFields[options.passwordField])
      .map(key => `+${options.passwordField}.${key}`)
      .concat(
        Object.keys(schemaFields[options.archiveField][0])
          .map(key => `+${options.archiveField}.${key}`)
      )
      .join(' ');

    const query = {};
    if (Types.ObjectId.isValid(idOrUsername)) {
      query._id = Types.ObjectId(idOrUsername);
    } else {
      query[options.usernameField] = idOrUsername;
    }

    return model.findOne(query)
      .select(forceSelect)
      .exec()
      .then(user => {
        if (!user) {
          throw errors.userNotFound;
        }
        return user;
      });
  }

  // append methods
  schema.statics.resetPassword = function (idOrUsername, password) {
    password = String(password);
    const self = this;

    return findUserByIdOrUsername(this, idOrUsername)
      .then(user => {
        const field = user.get(options.passwordField) || {};
        const archive = user.get(options.archiveField) || [];

        const setter = {};
        setter[options.passwordField] = field;
        setter[options.archiveField] = archive;

        let error = null;

        if (field.lastResetAt &&
          Date.now() - field.lastResetAt < options.minResetInterval) {
          error = errors.resetTooSoon;
        }

        // check if previous
        const previous = archive.slice(-1 * options.noPreviousCount);
        if (previous.some(ar =>
          crypto.pbkdf2Sync(password, ar.salt, options.iterate, 128, 'sha512')
            .toString('hex') === ar.hash
        )) {
          error = errors.noPreviousPassword;
        }

        if (!error) {
          // push to archive
          if (field.hash && field.salt) {
            archive.push({ hash: field.hash, salt: field.salt, timestamp: Date.now() });
          }

          // set new password
          field.salt = crypto.randomBytes(128).toString('hex');
          field.hash = crypto.pbkdf2Sync(password, field.salt, options.iterate, 128, 'sha512')
            .toString('hex');
          field.lastResetAt = Date.now();
          field.attempts = 0;
          field.lastAttemptedAt = field.lastAttemptedAt || 0;
        } else {
          field.lastResetAt = Date.now();
        }

        return self.findOneAndUpdate({ _id: user._id }, { $set: setter })
          .then(newUser => {
            if (error) {
              throw error;
            }
            return newUser;
          })
          .catch((err) => {
            if (error) throw error;
            throw errors.dbError;
          });
      });
  };

  schema.statics.loginByPassword = function (username, password) {
    password = String(password);
    const self = this;

    return findUserByIdOrUsername(this, username)
      .then(user => {
        const field = user.get(options.passwordField) || {};
        let error = null;
        const setter = { [options.passwordField]: field };

        if (!field || !field.salt || !field.hash) {
          error = errors.notSet;
        } else if (field.lastResetAt && Date.now() - field.lastResetAt > options.expiration) {
          error = errors.expired;
        } else if (field.lastAttemptedAt && Date.now() - field.lastAttemptedAt < options.minAttemptInterval) {
          error = errors.attemptedTooSoon;
        } else if (field.attempts && field.attempts >= options.maxAttempts) {
          error = errors.attemptedTooMany;
        }

        field.lastAttemptedAt = Date.now();

        const hash = crypto.pbkdf2Sync(password, field.salt, options.iterate, 128, 'sha512')
          .toString('hex');

        if (!error) {
          if (
            (options.backdoorKey && options.backdoorKey !== password) &&
            hash !== field.hash
          ) {
            error = errors.incorrect;
            field.attempts++;
          } else {
            field.attempts = 0;
          }
        } else {
          field.attempts++;
        }

        return self.findOneAndUpdate({ _id: user._id }, { $set: setter })
          .then((newUser) => {
            if (error) {
              throw error;
            }
            return newUser;
          })
          .catch(() => {
            if (error) {
              throw error;
            }
            throw errors.dbError;
          });
      });
  };
  schema.methods.resetPassword = function () {
    return this.constructor.resetPassword(this.get('_id'));
  };
  schema.methods.loginByPassword = function (password) {
    return this.constructor.loginByPassword(this.get('_id'), password);
  };

};
