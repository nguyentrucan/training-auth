const express = require('express');
const { createUser, loginUserCtrl, handleRefreshToken, logout } = require('../controller/userCtrl');
const router = express.Router();

router.post('/register', createUser);
router.post('/login', loginUserCtrl);
router.post('/refreshtoken', handleRefreshToken);
router.post('/logout', logout);

module.exports = router;