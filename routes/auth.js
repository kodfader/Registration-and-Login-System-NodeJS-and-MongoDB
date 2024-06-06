const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const passwordComplexity = require('joi-password-complexity');
const User = require('../models/user');
const auth = require('../middlewares/auth');

const router = express.Router();

const signUpValidationSchema = Joi.object({
    username: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: passwordComplexity({
        min: 8,
        max: 30,
        lowerCase: 1,
        upperCase: 1,
        numeric: 1,
        symbol: 1,
        requirementCount: 4,
    }).required()
});

const loginValidationSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

router.post('/signup', async (req, res) => {
    const { error } = signUpValidationSchema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const { username, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).send('User already exists');

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            username,
            email,
            password: hashedPassword
        });

        await newUser.save();

        const token = jwt.sign({ _id: newUser._id }, 'your_jwt_secret_key', { expiresIn: '1h' });
        res.header('auth-token', token).send({ message: 'User registered successfully', token });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

router.post('/login', async (req, res) => {
    const { error } = loginValidationSchema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('Invalid email or password');

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send('Invalid email or password');

        const token = jwt.sign({ _id: user._id }, 'your_jwt_secret_key', { expiresIn: '1h' });
        res.header('auth-token', token).send({ message: 'Logged in successfully', token });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

router.post('/logout', auth, (req, res) => {
    res.header('auth-token', '').send({ message: 'Logged out successfully' });
});

module.exports = router;
