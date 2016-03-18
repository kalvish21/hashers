/**
 * Created by Kalyan Vishnubhatla on 2/18/16.
 */


var assert = require('assert');
var bcrypt = require('bcrypt');
var crypt = require('crypt3');
var crypto = require('crypto');


function PBKDF2PasswordHasher() {
    this.algorithm = "pbkdf2_sha256";
    this.iterations = 24000;
    this.len = 32;

    this.salt = function() {
        return crypto.randomBytes(8).toString('base64');
    }

    this.encode = function(password, salt) {
        var key = pbkdf2(password, salt, this.iterations, this.len).toString('base64');
        return this.algorithm + "$" + this.iterations + "$" + salt + "$" + key;
    }

    this.verify = function(password, hash_password) {
        var parts = hash_password.split('$');
        var iterations = parseInt(parts[1]);
        var salt = parts[2];
        var value = pbkdf2(password, salt, iterations, this.len).toString('base64');
        return value == parts[3];
    }

    this.mustUpdate = function(hash_password) {
        var parts = hash_password.split('$');
        return parseInt(parts[1]) != this.iterations;
    }

    // Below code is from node-pbkdf2
    //
    // https://www.npmjs.com/package/node-pbkdf2
    function pbkdf2(key, salt, iterations, dkLen) {
        var hLen = 32;
        assert(dkLen <= (Math.pow(2, 32) - 1) * hLen, 'requested key length too long');
        assert(typeof key == 'string' || Buffer.isBuffer(key), 'key must be a string or buffer');
        assert(typeof salt == 'string' || Buffer.isBuffer(salt), 'key must be a string or buffer');

        if (typeof key == 'string') key = new Buffer(key);
        if (typeof salt == 'string') salt = new Buffer(salt);

        var DK = new Buffer(dkLen);
        var T = new Buffer(hLen);
        var block1 = new Buffer(salt.length + 4);

        var l = Math.ceil(dkLen / hLen);
        var r = dkLen - (l - 1) * hLen;

        salt.copy(block1, 0, 0, salt.length);
        for (var i = 1; i <= l; i++) {
            block1.writeUInt32BE(i, salt.length);
            var U = crypto.createHmac('sha256', key).update(block1).digest();
            U.copy(T, 0, 0, hLen);

            for (var j = 1; j < iterations; j++) {
                U = crypto.createHmac('sha256', key).update(U).digest();
                for (var k = 0; k < hLen; k++) {
                    T[k] ^= U[k];
                }
            }

            var destPos = (i - 1) * hLen;
            var len = (i == l ? r : hLen);
            T.copy(DK, destPos, 0, len);
        }

        return DK;
    }
}


function PBKDF2SHA1PasswordHasher() {
    this.algorithm = "pbkdf2_sha1";
    this.iterations = 24000;
    this.len = 20;

    this.salt = function() {
        return crypto.randomBytes(8).toString('base64');
    }

    this.encode = function(password, salt) {
        var key = this.pbkdf2(password, salt, this.iterations, this.len).toString('base64');
        return this.algorithm + "$" + this.iterations + "$" + salt + "$" + key;
    }

    this.verify = function(password, hash_password) {
        var parts = hash_password.split('$');
        var iterations = parseInt(parts[1]);
        var salt = parts[2];
        var value = this.pbkdf2(password, salt, iterations, this.len).toString('base64');
        return value == parts[3];
    }

    this.mustUpdate = function(hash_password) {
        var parts = hash_password.split('$');
        return parseInt(parts[1]) != this.iterations;
    }

    this.pbkdf2 = function(key, salt, iterations, dkLen) {
        var dk = crypto.pbkdf2Sync(key, salt, parseInt(iterations), dkLen);
        return dk;
    }
}


function BCryptSHA256PasswordHasher() {
    this.algorithm = "bcrypt_sha256";
    this.iterations = 12;
    this.len = 32;

    this.salt = function() {
        return bcrypt.genSaltSync(this.iterations);
    }

    this.encode = function(password, salt) {
        password = crypto.createHash('sha256').update(password).digest("hex");
        var key = bcrypt.hashSync(password, salt);
        return this.algorithm + "$" + key;
    }

    this.verify = function(password, hash_password) {
        hash_password = hash_password.substring(this.algorithm.length + 1, hash_password.length);
        var shapassword = crypto.createHash('sha256').update(password).digest("hex");
        return bcrypt.compareSync(shapassword, hash_password);
    }

    this.mustUpdate = function(hash_password) {
        var parts = hash_password.split('$');
        return parseInt(parts[3]) != this.iterations;
    }
}


function BCryptPasswordHasher() {
    this.algorithm = "bcrypt";
    this.iterations = 12;
    this.len = 32;

    this.salt = function() {
        return bcrypt.genSaltSync(this.iterations);
    }

    this.encode = function(password, salt) {
        var key = bcrypt.hashSync(password, salt);
        return this.algorithm + "$" + key;
    }

    this.verify = function(password, hash_password) {
        hash_password = hash_password.substring(this.algorithm.length + 1, hash_password.length);
        return bcrypt.compareSync(password, hash_password);
    }

    this.mustUpdate = function(hash_password) {
        var parts = hash_password.split('$');
        return parseInt(parts[3]) != this.iterations;
    }
}


function SHA1PasswordHasher() {
    this.algorithm = "sha1";

    this.salt = function() {
        return generateRandomString(12);
    }

    this.encode = function(password, salt) {
        var hash_password = crypto.createHash('sha1').update(password + salt).digest("hex");
        return this.algorithm + "$" + salt + "$" + hash_password;
    }

    this.verify = function(password, hash_password) {
        var parts = hash_password.split('$');
        var compare = this.encode(password, parts[1]);
        return compare == hash_password;
    }

    this.mustUpdate = function(hash_password) {
        return false;
    }
}


function MD5PasswordHasher() {
    this.algorithm = "md5";

    this.salt = function() {
        return generateRandomString(12);
    }

    this.encode = function(password, salt) {
        var hash_password = crypto.createHash('md5').update(password + salt).digest("hex");
        return this.algorithm + "$" + salt + "$" + hash_password;
    }

    this.verify = function(password, hash_password) {
        var parts = hash_password.split('$');
        var compare = this.encode(password, parts[1]);
        return compare == hash_password;
    }

    this.mustUpdate = function(hash_password) {
        return false;
    }
}


function UnsaltedSHA1PasswordHasher() {
    this.algorithm = "unsalted_sha1";

    this.salt = function() {
        return '';
    }

    this.encode = function(password, salt) {
        var hash_password = crypto.createHash('sha1').update(password + salt).digest("hex");
        return "sha1$$" + hash_password;
    }

    this.verify = function(password, hash_password) {
        var compare = this.encode(password, this.salt());
        return compare == hash_password;
    }

    this.mustUpdate = function(hash_password) {
        return false;
    }
}


function UnsaltedMD5PasswordHasher() {
    this.algorithm = "unsalted_md5";

    this.salt = function() {
        return '';
    }

    this.encode = function(password, salt) {
        var hash_password = crypto.createHash('md5').update(password + salt).digest("hex");
        return hash_password;
    }

    this.verify = function(password, hash_password) {
        if (hash_password.startsWith("md5$$") && hash_password.length == 37) {
            hash_password = hash_password.substring(5, 37);
        }
        var compare = this.encode(password, this.salt());
        return compare == hash_password;
    }

    this.mustUpdate = function(hash_password) {
        return false;
    }
}


function CryptPasswordHasher() {
    this.algorithm = "crypt";

    this.salt = function() {
        return generateRandomString(2);
    }

    this.encode = function(password, salt) {
        var hash_password = crypt(password, salt);
        return this.algorithm + "$$" + hash_password;
    }

    this.verify = function(password, hash_password) {
        var parts = hash_password.split('$');
        var compare = this.encode(password, parts[2]);
        return compare == hash_password;
    }

    this.mustUpdate = function(hash_password) {
        return false;
    }
}


function generateRandomString(length) {
    var chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var result = '';
    for (var i = length; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
}



