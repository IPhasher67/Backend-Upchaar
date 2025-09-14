const { UserAuthModel } = require('../db');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }
    const existingUser = await UserAuthModel.findOne({
      $or: [{ email: email.toLowerCase() }, { phone }]
    });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email or phone already registered.' });
    }
    const user = new UserAuthModel({
      name,
      email: email.toLowerCase(),
      phone,
      password
    });
    await user.save();
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('User registration error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during registration.' });
  }
};
