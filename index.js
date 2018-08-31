/**
 * Created by Kalyan Vishnubhatla on 2/18/16.
 */


const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const argon2 = require('argon2-ffi').argon2i;
const util = require('util');
const randomBytes = util.promisify(crypto.randomBytes);


module.exports.mustUpdateHashedPassword = function(hash_password, default_algorithm) {
    const algorithm = this.identifyHasher(hash_password);
    if (algorithm == null) {
        throw "Could not identify the hashing algorithm!";
    }

    if (algorithm === default_algorithm) {
        const hash_alg = this.getHasher(algorithm);
        return hash_alg.mustUpdate(hash_password);
    }

    return true;
}


module.exports.identifyHasher = function(hash_password) {
    var algorithm = null;
    if (hash_password.length === 32 && hash_password.indexOf("$") === -1) {
        algorithm = "unsalted_md5";
    } else if (hash_password.length === 37 && hash_password.startsWith("md5$$")) {
        algorithm = "unsalted_md5";
    } else if (hash_password.length === 46 && hash_password.startsWith("sha1$$")) {
        algorithm = 'unsalted_sha1';
    } else {
        algorithm = hash_password.split('$')[0];
    }
    return algorithm;
}


module.exports.getHasher = function(algorithm) {
    if (algorithm == null) {
        return null;
    }

    switch (algorithm) {
        case "pbkdf2_sha256": {
            return new this.PBKDF2PasswordHasher();
        }

        case "argon2": {
            return new this.Argon2PasswordHasher();
        }

        case "pbkdf2_sha1": {
            return new this.PBKDF2SHA1PasswordHasher();
        }

        case "bcrypt_sha256": {
            return new this.BCryptSHA256PasswordHasher();
        }

        case "bcrypt": {
            return new this.BCryptPasswordHasher();
        }

        case "sha1": {
            return new this.SHA1PasswordHasher();
        }

        case "md5": {
            return new this.MD5PasswordHasher();
        }

        case "unsalted_sha1": {
            return new this.UnsaltedSHA1PasswordHasher();
        }

        case "unsalted_md5": {
            return new this.UnsaltedMD5PasswordHasher();
        }

        default: {
            return null;
        }
    }
}


module.exports.Argon2PasswordHasher = function() {
    this.algorithm = "argon2";
    this.version = 19;
    this.time_cost = 2;
    this.memory_cost = 512;
    this.parallelism_value = 2;
    this.hash_length = 16;

    this.salt = async function() {
        return await randomBytes(32)
    }

    this.encode = async function(password) {
        const options = {
            timeCost: this.time_cost,
            memoryCost: this.memory_cost,
            parallelism: this.parallelism_value,
            hashLength: this.hash_length
        };

        const salt = await this.salt();
        const hash = await argon2.hash(password, salt, options);
        return this.algorithm + hash;
    }

    this.verify = async function(password, hash_password) {
        hash_password = hash_password.substring(this.algorithm.length, hash_password.length);
        return await argon2.verify(hash_password, password);
    }

    this.mustUpdate = function(hash_password) {
        const parts = hash_password.split('$');
        if (parts[0] !== this.algorithm) {
            return true;
        }

        if (parts[2] !== this.version) {
            return true;
        }

        const options = "m=" + this.memory_cost + ",t=" + this.time_cost + ",p=" + this.parallelism_value;
        if (options !== parts[3]) {
            return true;
        }

        return false;
    }
}


module.exports.PBKDF2PasswordHasher = function() {
    this.algorithm = "pbkdf2_sha256";
    this.iterations = 120000;
    this.len = 32;

    this.salt = function() {
        return crypto.randomBytes(8).toString('base64');
    }

    this.encode = function(password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const salt = self.salt();
            crypto.pbkdf2(password, salt, self.iterations, self.len, 'sha256', function (err, derivedKey) {
                if (err) { return reject(err); }
                const key = new Buffer(derivedKey, 'binary').toString('base64');
                resolve(self.algorithm + "$" + self.iterations + "$" + salt + "$" + key);
            });
        });
    }

    this.verify = function(password, hash_password) {
        const self = this;

        return new Promise(function (resolve, reject) {
            if (!hash_password) {
                resolve(false);
            }
            const parts = hash_password.split('$');

            if (parts.length !== 4) {
                resolve(false);
            }

            const iterations = parseInt(parts[1]);
            const salt = parts[2];
            const value = parts[3];
            crypto.pbkdf2(password, salt, iterations, self.len, 'sha256', function (err, derivedKey) {
                if (err) { return reject(err); }
                return resolve(new Buffer(derivedKey, 'binary').toString('base64') === value);
            });
        });
    }

    this.mustUpdate = function(hash_password) {
        const parts = hash_password.split('$');
        return parseInt(parts[1]) !== this.iterations;
    }
}


module.exports.PBKDF2SHA1PasswordHasher = function() {
    this.algorithm = "pbkdf2_sha1";
    this.iterations = 120000;
    this.len = 20;

    this.salt = function() {
        return crypto.randomBytes(8).toString('base64');
    }

    this.encode = function(password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const salt = self.salt();
            const key = self.pbkdf2(password, salt, self.iterations, self.len).toString('base64');
            resolve(self.algorithm + "$" + self.iterations + "$" + salt + "$" + key);
        });
    }

    this.verify = function(password, hash_password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const parts = hash_password.split('$');
            const iterations = parseInt(parts[1]);
            const salt = parts[2];
            const value = self.pbkdf2(password, salt, iterations, self.len).toString('base64');
            resolve(value === parts[3]);
        });
    }

    this.mustUpdate = function(hash_password) {
        const parts = hash_password.split('$');
        return parseInt(parts[1]) !== this.iterations;
    }

    this.pbkdf2 = function(key, salt, iterations, dkLen) {
        const dk = crypto.pbkdf2Sync(key, salt, parseInt(iterations), dkLen, 'sha1');
        return dk;
    }
}


module.exports.BCryptSHA256PasswordHasher = function() {
    this.algorithm = "bcrypt_sha256";
    this.iterations = 12;

    this.salt = function() {
        return bcrypt.genSaltSync(this.iterations);
    }

    this.encode = function(password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const salt = self.salt();
            password = crypto.createHash('sha256').update(password).digest("hex");
            const key = bcrypt.hashSync(password, salt);
            resolve(self.algorithm + "$" + key);
        });
    }

    this.verify = function(password, hash_password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            hash_password = hash_password.substring(self.algorithm.length + 1, hash_password.length);
            const shapassword = crypto.createHash('sha256').update(password).digest("hex");
            resolve(bcrypt.compareSync(shapassword, hash_password));
        });
    }

    this.mustUpdate = function(hash_password) {
        const parts = hash_password.split('$');
        return parseInt(parts[3]) !== this.iterations;
    }
}


module.exports.BCryptPasswordHasher = function() {
    this.algorithm = "bcrypt";
    this.iterations = 12;

    this.salt = function() {
        return bcrypt.genSaltSync(this.iterations);
    }

    this.encode = function(password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const salt = self.salt();
            const key = bcrypt.hashSync(password, salt);
            resolve(self.algorithm + "$" + key);
        });
    }

    this.verify = function(password, hash_password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            hash_password = hash_password.substring(self.algorithm.length + 1, hash_password.length);
            resolve(bcrypt.compareSync(password, hash_password));
        });
    }

    this.mustUpdate = function(hash_password) {
        const parts = hash_password.split('$');
        return parseInt(parts[3]) !== this.iterations;
    }
}


module.exports.SHA1PasswordHasher = function() {
    this.algorithm = "sha1";

    this.salt = function() {
        return generateRandomString(12);
    }

    this.encode = function(password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const salt = self.salt();
            const hash_password = crypto.createHash('sha1').update(salt + password).digest("hex");
            resolve(self.algorithm + "$" + salt + "$" + hash_password);
        });
    }

    this.verify = function(password, hash_password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const parts = hash_password.split('$');
            const compare = self.algorithm + "$" + parts[1] + "$" +
                crypto.createHash('sha1').update(parts[1] + password).digest("hex");
            resolve(compare === hash_password);
        });
    }

    this.mustUpdate = function(hash_password) {
        return false;
    }
}


module.exports.MD5PasswordHasher = function() {
    this.algorithm = "md5";

    this.salt = function() {
        return generateRandomString(12);
    }

    this.encode = function(password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const salt = self.salt();
            const hash_password = crypto.createHash('md5').update(password + salt).digest("hex");
            resolve(self.algorithm + "$" + salt + "$" + hash_password);
        });
    }

    this.verify = function(password, hash_password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const parts = hash_password.split('$');
            var compare = crypto.createHash('md5').update(password + parts[1]).digest("hex");
            compare = self.algorithm + "$" + parts[1] + "$" + compare;
            resolve(compare === hash_password);
        });
    }

    this.mustUpdate = function(hash_password) {
        return false;
    }
}


module.exports.UnsaltedSHA1PasswordHasher = function() {
    this.algorithm = "unsalted_sha1";

    this.salt = function() {
        return '';
    }

    this.encode = function(password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const salt = self.salt();
            const hash_password = crypto.createHash('sha1').update(password + salt).digest("hex");
            resolve("sha1$$" + hash_password);
        });
    }

    this.verify = function(password, hash_password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const compare = "sha1$$" + crypto.createHash('sha1').update(password + self.salt()).digest("hex");
            resolve(compare === hash_password);
        });
    }

    this.mustUpdate = function(hash_password) {
        return false;
    }
}


module.exports.UnsaltedMD5PasswordHasher = function() {
    this.algorithm = "unsalted_md5";

    this.salt = function() {
        return '';
    }

    this.encode = function(password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            const hash_password = crypto.createHash('md5').update(password + self.salt()).digest("hex");
            resolve(hash_password);
        });
    }

    this.verify = function(password, hash_password) {
        const self = this;
        return new Promise(function (resolve, reject) {
            if (hash_password.startsWith("md5$$") && hash_password.length === 37) {
                hash_password = hash_password.substring(5, 37);
            }
            const compare = crypto.createHash('md5').update(password + self.salt()).digest("hex");
            resolve(compare === hash_password);
        });

    }

    this.mustUpdate = function(hash_password) {
        return false;
    }
}


function generateRandomString(length) {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var result = '';
    for (var i = length; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
}



