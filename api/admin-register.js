const { AdminAuthModel } = require('../db');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }
  try {
    const { name, position, email, department, password } = req.body;
    if (!name || !position || !email || !department || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }
    const existingAdmin = await AdminAuthModel.findOne({ email: email.toLowerCase() });
    if (existingAdmin) {
      return res.status(400).json({ success: false, message: 'Email already registered.' });
    }
    const admin = new AdminAuthModel({
      name,
      position,
      email: email.toLowerCase(),
      department,
      password
    });
    await admin.save();
    const token = jwt.sign(
      { adminId: admin._id, email: admin.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.status(201).json({
      success: true,
      message: 'Admin registered successfully',
      token,
      admin: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        department: admin.department,
        position: admin.position
      }
    });
  } catch (error) {
    console.error('Admin registration error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during admin registration.' });
  }
};
