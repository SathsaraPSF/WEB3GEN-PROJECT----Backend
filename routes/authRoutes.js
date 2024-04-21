const express = require('express');
const router = express.Router();
const cors = require('cors');
const { addUser, getUsers, login, addAdmin,authenticateToken } = require('../controllers/authController');

router.use(
    cors({
        origin: true
    })
);


router.post('/registerUser', authenticateToken, addUser); 
router.post('/registerAdmin', addAdmin); 
router.get('/users', authenticateToken, getUsers); 

// Public route for login
router.post('/login', login); 

module.exports = router;
