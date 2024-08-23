const express = require('express');
const router = express.Router();
const controller = require('../controllers/controller');

router.get('/auth',controller.googleOauth);

router.get('/auth-callback',controller.callback);

router.get('/token', controller.token);

router.get('/api/users', controller.api_middleware, controller.users);

module.exports = router;