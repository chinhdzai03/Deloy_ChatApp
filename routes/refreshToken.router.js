const router = require('express').Router();
const refreshTokenController = require('../controllers/refreshToken.controller');

router.get('/', refreshTokenController.handleRefreshToken);

module.exports = router;
