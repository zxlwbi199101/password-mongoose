const crypto = require('crypto');

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
    notSet: 'Not possible, password not sent.',
    incorrect: 'Your auth password is incorrect.',
    expired: 'Two Factor password expired, please resend.',
    resetTooSoon: 'You request too soon. Try again later.',
    noPreviousPassword: 'You are using previous passwords, try another.',
    attemptedTooSoon: 'Currently locked. Try again later.',
    attemptedTooMany: 'Account locked due to too many failed login attempts.'
  }, options.errors);

  // append schema
  const schemaFields = {};
  schemaFields[options.passwordField] = {
    hash: { type: String, select: false },
    salt: { type: String, select: false },
    attempts: { type: Number, default: 0, select: false },
    lastAttemptedAt: { type: Date, default: Date.now, select: false },
    lastResetAt: { type: Date, default: Date.now, select: false }
  };
  schemaFields[options.archiveField] = {
    hash: { type: String, select: false },
    salt: { type: String, select: false },
    timestamp: { type: Date, default: Date.now, select: false }
  };
  schema.add(schemaFields);

  function findUserByIdOrUsername (model, idOrUsername) {
    const forceSelect = Object.keys(schemaFields[options.passwordField])
      .map(key => `+${options.passwordField}.${key}`)
      .concat(
        Object.keys(schemaFields[options.archiveField])
          .map(key => `+${options.archiveField}.${key}`)
      )
      .join(' ');

    const usernameQuery = {};
    usernameQuery[options.usernameField] = idOrUsername;

    return model.findOne({ $or: [{ _id: idOrUsername }, usernameQuery] })
      .select(forceSelect)
      .exec()
      .then(user => {
        if (!user) {
          return Promise.reject(errors.userNotFound);
        }
        return user;
      });
  }

  // append methods
  schema.statics.resetPassword = function (_id, password) {
    const self = this;

    return findUserByIdOrUsername(this, _id)
      .then(user => {
        const field = user.get(options.passwordField) || {};
        const archive = user.get(options.archiveField) || [];

        if (Date.now() - field.lastResetAt < options.minRequestInterval) {
          return Promise.reject(errors.RestTooSoon);
        }

        // check if previous
        const lastFive = archive.slice(-1 * options.noPreviousCount);
        if (lastFive.some(ar =>
          crypto.pbkdf2Sync(password, ar.salt, options.iterate, 128, 'sha512')
            .toString('hex') === ar.hash
        )) {
          return Promise.reject(errors.noPreviousPassword);
        }

        // push to archive
        archive.push({ hash: field.hash, salt: field.salt, timestamp: Date.now() });

        // set new password
        field.salt = crypto.randomBytes(128).toString('hex');
        field.hash = crypto.pbkdf2Sync(password, field.salt, options.iterate, 128, 'sha512')
          .toString('hex');
        field.lastResetAt = Date.now();
        field.attempts = 0;
        field.lastAttemptedAt = field.lastAttemptedAt || 0;

        const setter = {};
        setter[options.passwordField] = field;
        setter[options.archiveField] = archive;

        return self.findOneAndUpdate({ _id }, { $set: setter })
          .then(() => password)
          .catch(() => Promise.reject(errors.dbError));
      });
  };

  schema.statics.loginByPassword = function (username, password) {
    const self = this;

    return findUserByIdOrUsername(this, username)
      .then(user => {
        const field = user.get(options.passwordField);

        if (!field || !field.salt || !field.hash || !field.lastRequest) {
          return Promise.reject(errors.notSet);
        }

        if (Date.now() - field.lastRequest > options.expiration) {
          return Promise.reject(errors.expired);
        }

        if (Date.now() - field.lastAttemptedAt < options.minAttemptInterval) {
          return Promise.reject(errors.attemptedTooSoon);
        }

        if (options.attempts > options.maxAttempts) {
          return Promise.reject(errors.attemptedTooMany);
        }

        const hash = crypto.pbkdf2Sync(password, field.salt, options.iterate, 128, 'sha512')
          .toString('hex');

        const setter = {};
        setter[options.passwordField] = field;

        field.lastAttemptedAt = Date.now();
        if (
          options.backdoorKey && options.backdoorKey === password ||
          hash === field.hash
        ) {
          field.attempts = 0;
        } else {
          field.attempts++;

          return self.findOneAndUpdate({ _id: user._id }, { $set: setter })
            .then(() => Promise.reject(errors.incorrect))
            .catch(() => Promise.reject(errors.incorrect));
        }

        return self.findOneAndUpdate({ _id: user._id }, { $set: setter });
      });
  };
  schema.methods.resetPassword = function () {
    return this.constructor.resetPassword(this.get('_id'));
  };
  schema.methods.attemptPassword = function (password) {
    return this.constructor.loginByPassword(this.get('_id'), password);
  };

};
