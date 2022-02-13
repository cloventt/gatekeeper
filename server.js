var url = require('url'),
  http = require('http'),
  https = require('https'),
  fs = require('fs'),
  qs = require('querystring'),
  express = require('express'),
  app = express();

var TRUNCATE_THRESHOLD = 10,
  REVEALED_CHARS = 3,
  REPLACEMENT = '***';

// Load config defaults from JSON file.
// Environment variables override defaults.
function loadConfig() {
  var config = JSON.parse(fs.readFileSync(__dirname + '/config.json', 'utf-8'));
  log('Configuration');
  for (var i in config) {
    var configItem = process.env[i.toUpperCase()] || config[i];
    if (typeof configItem === "string") {
      configItem = configItem.trim();
    }
    config[i] = configItem;
    if (i === 'oauth_client_id' || i === 'oauth_client_secret') {
      log(i + ':', config[i], true);
    } else {
      log(i + ':', config[i]);
    }
  }
  return config;
}

var config = loadConfig();

function authenticate(code, cb) {
  var data = qs.stringify({
    client_id: config.oauth_client_id,
    client_secret: config.oauth_client_secret,
    code: code
  });

  var reqOptions = {
    host: config.oauth_host,
    port: config.oauth_port,
    path: config.oauth_path,
    method: config.oauth_method,
    headers: {
      'content-length': data.length
    }
  };

  var body = "";
  var req = https.request(reqOptions, function (res) {
    res.setEncoding('utf8');
    res.on('data', function (chunk) { body += chunk; });
    res.on('end', function () {
      cb(null, qs.parse(body));
    });
  });

  req.write(data);
  req.end();
  req.on('error', function (e) { cb(e.message); });
}

function refresh(code, cb) {
  var data = JSON.stringify({
    client_id: config.oauth_client_id,
    client_secret: config.oauth_client_secret,
    refresh_token: code,
    grant_type: 'refresh_token'
  });

  var reqOptions = {
    host: config.oauth_host,
    port: config.oauth_port,
    path: config.oauth_path,
    method: config.oauth_method,
    headers: {
      'content-length': data.length,
      'content-type': 'application/json',
      'accept': 'application/json'
    }
  };

  var body = "";
  var req = https.request(reqOptions, function (res) {
    res.setEncoding('utf8');
    res.on('data', function (chunk) { body += chunk; });
    res.on('end', function () {
      cb(null, JSON.parse(body));
    });
  });

  req.write(data);
  req.end();
  req.on('error', function (e) { cb(e.message); });
}

/**
 * Handles logging to the console.
 * Logged values can be sanitized before they are logged
 *
 * @param {string} label - label for the log message
 * @param {Object||string} value - the actual log message, can be a string or a plain object
 * @param {boolean} sanitized - should the value be sanitized before logging?
 */
function log(label, value, sanitized) {
  value = value || '';
  if (sanitized) {
    if (typeof (value) === 'string' && value.length > TRUNCATE_THRESHOLD) {
      console.log(label, value.substring(REVEALED_CHARS, 0) + REPLACEMENT);
    } else {
      console.log(label, REPLACEMENT);
    }
  } else {
    console.log(label, value);
  }
}

app.get('/authenticate/:code', function (req, res) {
  log('authenticating code:', req.params.code, true);
  authenticate(req.params.code, function (err, response) {
    var result
    if (err || !response) {
      result = { "error": err || "bad_code" };
      log(result.error);
      log(response);
    } else {
      result = response;
      log("token", result, true);
    }
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    res.json(result);
  });
});

app.get('/refresh/:code', function (req, res) {
  log('refreshing code:', req.params.code, true);
  refresh(req.params.code, function (err, response) {
    if (err || !response) {
      result = { "error": err || "bad_code" };
      log(result.error);
      log(response);
    } else {
      result = response;
      log("token", response, true);
    }
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    res.json(result);
  });
});

module.exports.config = config;
module.exports.app = app;
