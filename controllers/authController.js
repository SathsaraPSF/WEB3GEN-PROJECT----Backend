
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const UserModel = require('../models/user');


const authenticateToken = async (req, res, next) => {
    // Extract the token from the request headers
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authorization token missing' });
    }

    try {
        // Verify and decode the token
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        // Retrieve user information from the database using the user ID from the token
        const user = await UserModel.findById(decodedToken.userId);

        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }

        // Check if the user is an admin
        if (user.type !== 'ADMIN') {
            return res.status(403).json({ error: 'Unauthorized: User is not an admin' });
        }

        // Attach the user object to the request for further processing
        req.user = user;

        // Proceed to the next middleware or route handler
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Function to generate JWT token
const generateToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' }); 
};

const addAdmin = async (req, res) => {
    try {
        const { type, basic_info, contact_info, auth_info } = req.body;

        // Ensure that the password is provided in the request body for admin
        if (!auth_info || !auth_info.password) {
            return res.status(400).json({ error: 'Password is required for ADMIN user' });
        }

        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(auth_info.password, 10); // Use appropriate salt rounds

        // Create a new admin user record with hashed password
        const adminUser = new UserModel({
            type,
            status: 'ONBOARD',
            basic_info,
            contact_info,
            auth_info: { password: hashedPassword } // Record hashed password for admin user
        });

        // Save the new admin user record to the database
        await adminUser.save();

        res.status(201).json({ message: 'Admin added successfully' });
    } catch (error) {
        console.error('Error adding admin:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};



// API for Login
const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        const user = await UserModel.findOne({ 'contact_info.email': email, 'type': 'ADMIN' });

        if (!user) {
            return res.status(401).json({ error: 'Invalid user name' });
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.auth_info.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Generate JWT token
        const token = generateToken(user._id);

        // Update user record with token
        user.token = token;
        await user.save();

        res.status(200).json({ token });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};


// API for Registering User
const addUser = async (req, res) => {
    try {
        // Extract user data from the request body
        const { type, basic_info, contact_info, auth_info } = req.body;

        // Authenticate the token
        authenticateToken(req, res, async () => {
            // Check if user is authenticated as ADMIN
            if (req.user.type !== 'ADMIN') {
                return res.status(401).json({ error: 'Forbidden: User is not an admin' });
            }

            // Create a new user record without recording the password
            const newUser = new UserModel({
                type,
                status: 'ONBOARD',
                basic_info,
                contact_info,
                auth_info: { password: '' } // Password will be empty for regular users
            });

            // Save the new user record to the database
            await newUser.save();

            // Return a success response
            return res.status(201).json({ message: 'User added successfully' });
        });
    } catch (error) {
        // Handle any errors that occur during the process
        console.error('Error adding user:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};



const getUsers = async (req, res) => {
    try {
        // Authenticate the token
        authenticateToken(req, res, async () => {
            // Check if user is authenticated as ADMIN
            if (req.user.type !== 'ADMIN') {
                return res.status(401).json({ error: 'Forbidden: User is not an admin' });
            }

            // Retrieve all USERS except ADMIN
            const users = await UserModel.find({ type: 'USER' }, '-auth_info');

            res.status(200).json(users);
        });
    } catch (error) {
        console.error('Error retrieving users:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};


module.exports = { login, addUser, getUsers , addAdmin, authenticateToken};
 